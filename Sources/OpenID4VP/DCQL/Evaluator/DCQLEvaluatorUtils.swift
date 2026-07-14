import Foundation
import SwiftCBOR

private let className = "DCQLUtils"

func expandCredentialTag(_ credential: Credential, jsonLdExpander: JsonLdExpanderCallback?) async throws -> TaggedCredential {
    switch credential.format {
    case .ldp_vc:
        guard let jsonLdExpander = jsonLdExpander else {
            throw InvalidData(message: "JsonLdExpander is required to process w3c credentials", className: className)
        }
        guard let credentialData = credential.data.value as? [String:Any] else {
            throw InvalidData(message: "Credential data is not in the expected format", className: className)
        }
        let credentialSubjectId: String? = (credentialData["credentialSubject"] as? [String:Any] ?? [:])["id"] as? String
        let expandedCredential = try await jsonLdExpander(credentialData)
        return W3cTaggedCredential(
            credentialFormat: credential.format,
            hasCryptographicHolderBinding: credentialSubjectId != nil,
            types: expandedCredential["@type"] as? [String] ?? []
        )
    case .mso_mdoc:
        let (_, decodedMdocCredential) = try decodeMdoc(credential.data, className: className)
        let (_, docTypeString) = try extractMdocDocType(from: decodedMdocCredential, className: className)
        
        return MdocTaggedCredential(
            hasCryptographicHolderBinding: true,
            doctype: docTypeString
        )
    case .dc_sd_jwt, .vc_sd_jwt:
        let (_, sdJWTPayload, _ ) = try extractSdJwtPayload(credential.data, className: className)
        
        return SdJwtTaggedCredential(
            credentialFormat: credential.format,
            hasCryptographicHolderBinding: sdJWTPayload["cnf"] != nil,
            vct: sdJWTPayload["vct"] as? String ?? ""
        )
    }
}


func convertToProcessedCredentials(_ filteredWalletCredentialIds: [String], _ credentialIdToCredential: [String: Credential]) throws -> [String: any ProcessedCredential] {
    var processedCredentials: [String: any ProcessedCredential] = [:]
    
    for credentialId in filteredWalletCredentialIds {
        guard let credential = credentialIdToCredential[credentialId] else { continue }
        
        switch credential.format {
        case .ldp_vc:
            guard let credentialData = credential.data.value as? [String:Any] else {
                throw InvalidData(message: "Credential data is not in the expected format", className: className)
            }
            
            processedCredentials[credentialId] = (W3cProcessedCredential(
                credentialId: credential.credentialId,
                credentialFormat: credential.format,
                claims: credentialData // TODO: recheck and rename it accordingly // credentialSubject, fullName
            ))
            
        case .mso_mdoc:
            let (_, decodedMdocCredential) = try decodeMdoc(credential.data, className: className)
            
            var namespaces: [String: [String: Any]] = [:]
            if let issuerSignedCBOR = getValueFromCBORMap(cborMap: decodedMdocCredential, key: "issuerSigned"),
               let nameSpacesCBOR = getValueFromCBORMap(cborMap: issuerSignedCBOR, key: "nameSpaces") {
                
                if case let .map(items) = nameSpacesCBOR {
                    for (nsKey, nsValue) in items {
                        if let nsString = extractStringFromCBOR(nsKey), case let .array(elementItems) = nsValue {
                            var elements: [String: Any] = [:]
                            for item in elementItems {
                                if case let .tagged(tag, .byteString(bstr)) = item, tag.rawValue == 24,
                                   let decodedItem = try? CBOR.decode(bstr) {
                                    
                                    if let elementIdCBOR = getValueFromCBORMap(cborMap: decodedItem, key: "elementIdentifier"),
                                       let elementId = extractStringFromCBOR(elementIdCBOR),
                                       let elementValueCBOR = getValueFromCBORMap(cborMap: decodedItem, key: "elementValue") {
                                        
                                        if let unwrappedValue = unwrapCbor(elementValueCBOR) {
                                            elements[elementId] = unwrappedValue
                                        }
                                    }
                                }
                            }
                            namespaces[nsString] = elements
                        }
                    }
                }
            }
            
            processedCredentials[credentialId] = (MdocProcessedCredential(
                credentialId: credential.credentialId,
                namespaces: namespaces
            ))
            
        case .dc_sd_jwt, .vc_sd_jwt:
            let (_, _, fullyResolvedClaims) = try extractSdJwtPayload(credential.data, className: className, decodeDisclosures: true)
            
            processedCredentials[credentialId] = (SdJwtProcessedCredential(
                credentialId: credential.credentialId,
                credentialFormat: credential.format,
                claims: fullyResolvedClaims
            ))
        }
    }
    
    return processedCredentials
}

func resolveClaimsPathPointer(_ path: [AnyCodable], in claims: [String: Any]) throws -> Any? {
    var selectedElement: Any? = claims
    for (i, pathPointer) in path.enumerated() {
        if let pathPointerValue = pathPointer.value as? String {
            if let selectedElementObject = selectedElement as? [String: Any] {
                if let value = selectedElementObject[pathPointerValue] {
                    selectedElement = value
                } else {
                    // non-existent key - handle the edge case here (remove from selection)
                    selectedElement = nil
                }
            } else {
                // Selected element is an array of objects due to previous path pointer being null
                if (i > 0 && isNullPathPointer(path[i-1].value)) {
                    if let selectedArray = selectedElement as? [[String: Any]] {
                        var selectedValues: [Any] = []
                        for obj in selectedArray {
                            if let value = obj[pathPointerValue] {
                                selectedValues.append(value)
                            }
                        }
                        selectedElement = selectedValues.isEmpty ? nil : selectedValues
                    } else {
                        throw InvalidData(message: "currently selected element(s) is not an object", className: className)
                    }
                } else {
                    throw InvalidData(message: "currently selected element(s) is not an object", className: className)
                }
            }
        } else if let pathPointerValue = intIndex(from: pathPointer.value) {
            if let selectedArray = selectedElement as? [Any] {
                if (pathPointerValue >= selectedArray.count || pathPointerValue < 0) {
                    selectedElement = nil
                } else {
                    selectedElement = selectedArray[pathPointerValue]
                }
            } else {
                throw InvalidData(message: "currently selected element(s) is not an array", className: className)
            }
        } else if isNullPathPointer(pathPointer.value) {
            if let selectedArray = selectedElement as? [Any] {
                selectedElement = selectedArray
            } else {
                throw InvalidData(message: "currently selected element(s) is not an array", className: className)
            }
        } else {
            throw InvalidData(message: "Unexpected path pointer component", className: className)
        }
    }
    return selectedElement
}

private func isNullPathPointer(_ value: Any?) -> Bool {
    return value is NSNull || String(describing: value) == "nil" || String(describing: value) == "Optional(nil)" || String(describing: value).contains("Optional<Any>.none") || String(describing: value).contains("Optional<NSNull>.some") || String(describing: value) == "Optional<Any>(nil)"
}

// A JSON array index in a claims path may decode as Int, Double, or NSNumber
// depending on the parser (AnyCodable often yields Double), so accept any integral
// numeric form — otherwise paths like `["@context", 0]` throw and resolve to nil.
private func intIndex(from value: Any?) -> Int? {
    if let i = value as? Int { return i }
    if let d = value as? Double, d == d.rounded() { return Int(d) }
    if let n = value as? NSNumber { return n.intValue }
    return nil
}
