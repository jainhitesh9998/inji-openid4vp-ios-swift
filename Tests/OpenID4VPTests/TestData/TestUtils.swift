import Foundation
@testable import OpenID4VP
import XCTest

func createVerifiers(from verifierList: [[String: Any]]) -> [Verifier] {
    var verifiers: [Verifier] = []
    
    for verifierData in verifierList {
        if let clientId = verifierData[AuthorizationRequestFieldConstants.clientId] as? String,
           let responseUris = verifierData["response_uris"] as? [String] {
            let jwksUri = verifierData["jwks_uri"] as? String
            
            if let allowUnsignedRequest = verifierData["allow_unsigned_request"] as? Bool {
                let verifier = Verifier(clientId: clientId, responseUris: responseUris, jwksUri: jwksUri, allowUnsignedRequest: allowUnsignedRequest)
                verifiers.append(verifier)
                continue
            }
            let verifier = Verifier(clientId: clientId, responseUris: responseUris)
            verifiers.append(verifier)
            
        }
    }
    
    return verifiers
}

func createUrlEncodedAuthorizationRequest(
    requestParams: [String: Any?],
    verifierSentAuthRequestByReference: Bool? = false,
    clientIdPrefix: ClientIdPrefix,
    applicableFields: [String]? = nil,
    specVersion: SpecVersion = .v1,
    addEncryptionClientMetadataParams: Bool = true
) -> String {
    let paramList: [String]
    if verifierSentAuthRequestByReference == true {
        paramList = applicableFields ?? authRequestParamsByReference
    } else {
        paramList = applicableFields ?? authRequestClientIdPrefixMap[clientIdPrefix]!
    }
    
    let authorizationRequestParam = createAuthorizationRequest(paramList: paramList, requestParams: requestParams, specVersion: specVersion, addEncryptionClientMetadataParams: addEncryptionClientMetadataParams)
    let queryString = encodeToQueryParameters(authorizationRequestParam)
    
    return "OPENID4VP://authorize?\(queryString)"
}

private func encodeToQueryParameters(_ parameters: [String: Any?]) -> String {
    let queryString = parameters.compactMap { (key, value) -> String? in
        guard let encodedKey = key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) else { return nil }
        
        let encodedValue: String
        if let stringValue = value as? String {
            encodedValue = stringValue
        } else if let jsonData = try? JSONSerialization.data(withJSONObject: value as Any, options: []),
                  //       stringify client_metdata and presentation defintiion
                  let jsonString = String(data: jsonData, encoding: .utf8) {
            encodedValue = jsonString
        } else {
            return nil // Skip values that can't be converted
        }
        
        guard var finalEncodedValue = encodedValue.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) else { return nil }
        finalEncodedValue = finalEncodedValue.replacingOccurrences(of: "+", with: "%2B")
        return "\(encodedKey)=\(finalEncodedValue)"
    }.joined(separator: "&")
    
    return queryString
}

func createAuthorizationRequest(
    paramList: [String],
    requestParams: [String: Any?],
    isSigned: Bool = false,
    specVersion: SpecVersion = .v1,
    isPresentationExchangeByReference: Bool = false,
    addEncryptionClientMetadataParams: Bool = true
) -> [String: Any?] {
    var requestParamsKeysList = paramList
    if(specVersion == .v1) {
        requestParamsKeysList = requestParamsKeysList + ["dcql_query"]
    } else {
        if(isPresentationExchangeByReference) {
            requestParamsKeysList = requestParamsKeysList + ["presentation_definition_uri"]
        } else {
            requestParamsKeysList = requestParamsKeysList + ["presentation_definition"]
        }
    }
    var authorizationRequestParam: [String: Any?] = [:]
    for param in requestParamsKeysList {
        if let value = requestParams[param], value != nil {
            // the value is version specific pick the internal value accordingly
            if let versionSpecificValue = (value as? [SpecVersion: Any]) {
                authorizationRequestParam[param] = versionSpecificValue[specVersion]
            } else {
                authorizationRequestParam[param] = value
            }
            
        }
    }
    
    if(!addEncryptionClientMetadataParams) {
        if let clientMetadata = authorizationRequestParam["client_metadata"] as? [String: Any] {
            var modifiedClientMetadata = clientMetadata
            // Draft 23 specific encryption metadata fields
            modifiedClientMetadata["authorization_signed_response_alg"] = nil
            modifiedClientMetadata["authorization_encrypted_response_alg"] = nil
            modifiedClientMetadata["authorization_encrypted_response_enc"] = nil
            
            // Spec version 1 specific encryption metadata fields
            modifiedClientMetadata["encrypted_response_enc_values_supported"] = nil
            
            authorizationRequestParam["client_metadata"] = modifiedClientMetadata
        }
    }
    if(isSigned){
        let request = JWSUtil.create(payload: authorizationRequestParam as [String : Any])
        authorizationRequestParam = [
            AuthorizationRequestFieldConstants.request: request,
            AuthorizationRequestFieldConstants.clientId: requestParams[AuthorizationRequestFieldConstants.clientId] ?? ""
        ]
    }
    return authorizationRequestParam
}

func createAuthorizationRequestObject(
    clientIdPrefix: ClientIdPrefix,
    authorizationRequestParams: [String: Any],
    jwsHeaderData: [String: Any]? = nil,
    applicableFields: [String]? = nil,
    addValidSignature: Bool = true,
    isPresentationExchangeByReference: Bool = false,
    specVersion: SpecVersion = .v1,
    addEncryptionClientMetadataParams: Bool = true
) -> String {
    var parametersList = applicableFields ?? authRequestClientIdPrefixMap[clientIdPrefix]!
    if(specVersion == .v1) {
        parametersList += ["dcql_query"]
    } else {
        if(isPresentationExchangeByReference) {
            parametersList += ["presentation_definition_uri"]
        } else {
            parametersList += ["presentation_definition"]
        }
    }
    let authorizaitonRequestParameters = createAuthorizationRequest(paramList: parametersList, requestParams: authorizationRequestParams, specVersion: specVersion, isPresentationExchangeByReference: isPresentationExchangeByReference, addEncryptionClientMetadataParams: addEncryptionClientMetadataParams)
//        authorizaitonRequestParameters[AuthorizationRequestFieldConstants.walletNonce] = "mock-nonce"
    
    return JWSUtil.create(header: jwsHeaderData, payload: authorizaitonRequestParameters as [String : Any], addValidSignature: addValidSignature)
}


func createUnsignedAuthorizationRequestObject(
    clientIdPrefix: ClientIdPrefix,
    authorizationRequestParams: [String: Any],
    applicableFields: [String]? = nil,
    specVersion: SpecVersion = .v1
) throws -> String {
    let parametersList = applicableFields ?? authRequestClientIdPrefixMap[clientIdPrefix]!
    let authorizationRequestParameters = createAuthorizationRequest(paramList: parametersList, requestParams: authorizationRequestParams, specVersion: specVersion)
    let payload = authorizationRequestParameters.compactMapValues { $0 }
    // Compact JWT with an "alg": "none" JOSE header and an empty signature (RFC 7519 §6.1).
    return try JWSHandler.createUnsignedJWS(
        header: ["typ": "oauth-authz-req+jwt", "alg": "none"],
        payload: payload
    )
}

func convertToJsonString(_ data: [String: Any]) -> String {
    let jsonData = try? JSONSerialization.data(withJSONObject: data, options: [])
    let jsonString = String(data: jsonData!, encoding: .utf8)
    return jsonString!
}

func convertToJsonString(_ array: [Any]) -> String {
    do {
        let jsonData = try JSONSerialization.data(withJSONObject: array, options: .prettyPrinted)
        if let jsonString = String(data: jsonData, encoding: .utf8) {
            return jsonString
        }
    } catch {
        print("Error converting array to JSON: \(error)")
    }
    return ""
}

func convertToJsonString<T: Encodable>(_ object: T) -> String {
    do {
        let jsonData = try JSONEncoder().encode(object)
        return String(data: jsonData, encoding: .utf8) ?? ""
    } catch {
        print("Error converting object to JSON string: \(error)")
        return "{}"
    }
}

func convertToDictionary<T: Encodable>(object: T) -> [String: Any]? {
    guard let data = try? JSONEncoder().encode(object) else {
        return nil
    }
    return try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
}

func addingPercentEncoding(_ value: String) -> String {
    return value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value
}

func mergeMaps<K, V>(_ maps: [K: V]...) -> [K: V] {
    return maps.reduce(into: [:]) { result, map in
        result.merge(map) { (_, new) in new }
    }
}


// Assert equality of errors
public func == (lhs: Error, rhs: Error) -> Bool {
    guard type(of: lhs) == type(of: rhs) else { return false }
    let error1 = lhs as NSError
    let error2 = rhs as NSError
    return error1.domain == error2.domain && error1.code == error2.code && "\(lhs)" == "\(rhs)"
}

extension Equatable where Self : Error {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs as Error == rhs as Error
    }
}

func decodeQueryValue(_ value: String) -> String {
    return value.removingPercentEncoding ?? value
}

func jsonString(_ any: Any, prettyPrinted: Bool = false) -> String? {
    guard JSONSerialization.isValidJSONObject(any) else {
        print("Not a valid JSON object")
        return nil
    }
    
    do {
        let options: JSONSerialization.WritingOptions = prettyPrinted ? [.prettyPrinted] : []
        let data = try JSONSerialization.data(withJSONObject: any, options: options)
        return String(data: data, encoding: .utf8)
    } catch {
        print("Error serializing to JSON: \(error)")
        return nil
    }
}

func createInstance<T: Decodable>(_ json: [String: Any], as type: T.Type) -> T {
    let jsonData = try? JSONSerialization.data(withJSONObject: json, options: [])
    let decoder = JSONDecoder()
    do {
        return try decoder.decode(T.self, from: jsonData!)
    } catch {
        print("Error decoding JSON: \(error)")
        return (try? decoder.decode(T.self, from: jsonData!))!
    }
}

func createRequestUriResponse(_ body: String, httpUrlResponse: HTTPURLResponse? = nil, specVersion: SpecVersion = .v1) -> (body: String, httpUrlResponse: HTTPURLResponse) {
    let defaultHttpUrlResponse = httpUrlResponseForJWS
    let modifiedResponse: HTTPURLResponse = httpUrlResponse ?? defaultHttpUrlResponse
    
    return (body: body, httpUrlResponse: modifiedResponse)
}

func getMockAuthorizationRequest(responseMode: ResponseMode = .directPost, responseType: String? = nil, responseModeValue: String? = nil, specVersion: SpecVersion = .v1, dcqlQuery: DCQLQuery? = nil, presentationDefinition: PresentationDefinition? = nil) -> AuthorizationRequest {
    let responseType = responseType ?? ResponseType.vp_token.rawValue
    
    if(specVersion == .draft23) {
        return AuthorizationPresentationExchangeRequest(
            clientId: "client_id",
            responseType: responseType,
            responseMode: responseModeValue ?? responseMode.rawValue,
            responseUri: "https://mock-verifier.com",
            redirectUri: "1234",
            nonce: "tHwahwI6M5_Cd_Sj5k2_Aw",
            walletNonce: nil,
            state: "state",
            presentationDefinition: presentationDefinition ?? mockPresentationDefinitionObject,
            clientMetadata: mockClientMetadataSpecVersionDraft23[.directPostJwt]
        )
    }

    return AuthorizationDcqlRequest(
        clientId: "client_id",
        responseType: responseType,
        responseMode: responseModeValue ?? responseMode.rawValue,
        responseUri: "https://mock-verifier.com",
        redirectUri: "1234",
        nonce: "tHwahwI6M5_Cd_Sj5k2_Aw",
        walletNonce: nil,
        state: "state",
        dcqlQuery: dcqlQuery ?? validDcqlQuery,
        clientMetadata: mockClientMetadataSpecVersion1[responseMode]
    )
}

func createWalletConfig(
    vpFormatsSupported: [VPFormatType: VPFormatSupported] = [
        .ldp_vc: LdpVpFormatSupported(),
        .mso_mdoc: MsoMdocVpFormatSupported(),
        .dc_sd_jwt: SdJwtVpFormatSupported()
    ],
    clientIdPrefixesSupported: [ClientIdPrefix] = [.preRegistered, .redirectUri, .decentralizedIdentifier],
    requestObjectSigningAlgValuesSupported: [SignatureAlgorithm]? = [.edDsa],
    authorizationEncryptionAlgValuesSupported: [EncryptionAlgorithm]? = [.ecdhES],
    authorizationEncryptionEncValuesSupported: [EncryptionMethod]? = [.a256GCM],
    responseTypesSupported: [ResponseType] = [.vp_token],
    responseMode: ResponseMode = .directPost,
    trustedVerifiers: [Verifier] = preRegisteredVerifiers,
    validatePreregisteredVerifier: Bool = true
) -> WalletConfig {
    return WalletConfig(
        vpFormatsSupported: vpFormatsSupported,
        clientIdPrefixesSupported: clientIdPrefixesSupported,
        requestObjectSigningAlgValuesSupported: requestObjectSigningAlgValuesSupported,
        authorizationEncryptionAlgValuesSupported: authorizationEncryptionAlgValuesSupported,
        authorizationEncryptionEncValuesSupported: authorizationEncryptionEncValuesSupported,
        responseTypesSupported: responseTypesSupported,
        trustedVerifiers: trustedVerifiers,
        validateTrustedVerifier: validatePreregisteredVerifier
    )
}

func ldpVC(
    credentialType : String = "IDCardCredential",
    context: [Any] = [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1",
        [
            "sec": "https://w3id.org/security#"
        ],
    ],
    addHolderBinding: Bool = true
) -> [String: Any] {
    var data : [String: Any] = [
        "@context": context,
        "id": "https://example.com/credentials/1872",
        "type": [
            "VerifiableCredential",
            credentialType
        ],
        "issuer": [
            "id": "did:example:issuer"
        ],
        "issuanceDate": "2010-01-01T19:23:24Z",
        "credentialSubject": [
            "id": didJwkKey,
            "given_name": "MockUser",
            "family_name": "Mockister",
            "birthdate": "1949-01-22"
        ],
        "proof": [
            "type": "Ed25519Signature2018",
            "created": "2021-03-19T15:30:15Z",
            "jws": "eyJhb...JQdBw",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:example:issuer#keys-1"
        ]
    ]
    if(addHolderBinding) {
        data["credentialSubject"] = [
            "id": didJwkKey,
            "given_name": "MockUser",
            "family_name": "Mockister",
            "birthdate": "1949-01-22"
        ]
    } else {
        data["credentialSubject"] = [
            "given_name": "MockUser",
            "family_name": "Mockister",
            "birthdate": "1949-01-22"
        ]
    }
    return data
}

