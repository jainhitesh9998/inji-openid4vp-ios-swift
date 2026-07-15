import Foundation

private let className = "UnsignedLdpVPTokenBuilder"

class UnsignedLdpVPTokenBuilder: UnsignedVPTokenBuilder {
    private let id: String
    public let specVersion: SpecVersion
    public let authorizationRequest: AuthorizationRequest
    public let walletConfig: WalletConfig
    
    static let internalPath: String = "verifiableCredential"
    
    public init(
        authorizationRequest: AuthorizationRequest,
        specVersion: SpecVersion,
        id: String,
        walletConfig: WalletConfig = WalletConfig()
    ) {
        self.authorizationRequest = authorizationRequest
        self.specVersion = specVersion
        self.id = id
        self.walletConfig = walletConfig
    }
    
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) {
        guard (authorizationRequest as? AuthorizationPresentationExchangeRequest) != nil else {
            throw InvalidData(message: "Expected AuthorizationPresentationExchangeRequest for Presentation Exchange flow", className: className)
        }
        
        var unsignedVPTokens: [UnsignedVPToken] = []
        var vpTokenSigningPayloads : [String: LdpVP] = [:]
        
        for index in 0..<credentialInputDescriptorMappings.count {
            var credentialInputDescriptorMapping = credentialInputDescriptorMappings[index]
            let identifier = UUIDGenerator.generateUUID()
            
            credentialInputDescriptorMapping.identifier = identifier
            credentialInputDescriptorMapping.nestedPath = "$.\(Self.internalPath)[0]"
            credentialInputDescriptorMappings[index] = credentialInputDescriptorMapping
            
            let credential = credentialInputDescriptorMapping.credential
            
            let verifiableCredentials: [AnyCodable] = [credential]


            let result = try extractHolderAndSignatureSuite(credential, walletHolder: credentialInputDescriptorMapping.walletHolder)

            let (vpTokenSigningPayload, unsignedVPToken) = try await buildPayloadAndUnsignedVPToken(
                identifier: identifier,
                with: verifiableCredentials,
                signatureSuite: result.signatureSuite,
                holder: sanitize(result.holder)
            )
            
            vpTokenSigningPayloads[identifier] = vpTokenSigningPayload
            if let unsignedVPToken = unsignedVPToken {
                unsignedVPTokens.append(unsignedVPToken)
            }
            
        }
        
        return (vpTokenSigningPayloads, unsignedVPTokens)
    }
    
    func build(credentialToCredentialQueryIdMappings: inout [CredentialToCredentialQueryIdMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]) {
        guard let authorizationRequest = authorizationRequest as? AuthorizationDcqlRequest else {
            throw InvalidData(message: "Expected AuthorizationDcqlRequest for DCQL flow", className: className)
        }
        var unsignedVPTokens: [UnsignedVPToken] = []
        var vpTokenSigningPayloads : [String: LdpVP] = [:]
        
        for index in 0..<credentialToCredentialQueryIdMappings.count {
            var credentialToCredentialQueryIdMapping = credentialToCredentialQueryIdMappings[index]
            let identifier = UUIDGenerator.generateUUID()
            
            credentialToCredentialQueryIdMapping.identifier = identifier
            credentialToCredentialQueryIdMappings[index] = credentialToCredentialQueryIdMapping
            
            let (credential, credentialQueryId) = (credentialToCredentialQueryIdMapping.credential, credentialToCredentialQueryIdMapping.credentialQueryId)
            
            let verifiableCredentials: [AnyCodable] = [credential]
            
            let mappedCredentialQuery = try authorizationRequest.dcqlQuery.credentials.first(where: { $0.id == credentialQueryId }) ?? {
                throw InvalidData(message: "No matching credential query found for credential query id: \(credentialQueryId)", className: className)
            }()
            
            if(!mappedCredentialQuery.requireCryptographicHolderBinding) {
                vpTokenSigningPayloads[identifier] = .vc(LdpVCToken(verifiableCredential: credential))
                continue
            }
            
            let result = try extractHolderAndSignatureSuite(credential)
            let (vpTokenSigningPayload, unsignedVPToken) = try await buildPayloadAndUnsignedVPToken(
                identifier: identifier,
                with: verifiableCredentials,
                signatureSuite: result.signatureSuite,
                holder: sanitize(result.holder)
            )
            
            vpTokenSigningPayloads[identifier] = vpTokenSigningPayload
            if let unsignedVPToken = unsignedVPToken {
                unsignedVPTokens.append(unsignedVPToken)
            }
            
        }
        
        return (vpTokenSigningPayloads, unsignedVPTokens)
    }
    
    private func buildPayloadAndUnsignedVPToken(identifier: String, with credentials: [AnyCodable], signatureSuite: String?, holder: String?) async throws -> (vpTokenSigningPayload: LdpVP, unsignedVPToken: UnsignedVPToken?) {
        // CCP fork: the VP-envelope @context uses VCDM **v2** to match the embedded
        // v2 credential. In v2 the `verifiableCredential` term carries `@context: null`,
        // which resets the nested VC's context so the VP envelope and the VC don't
        // layer v1+v2 protected terms (e.g. VerifiableCredential/validUntil). With a
        // v1 envelope a strict verifier (Digital Bazaar / ccp-pilot) raises "protected
        // term redefinition" and returns HTTP 400 on the VP POST.
        var context: [String] = ["https://www.w3.org/ns/credentials/v2"]
        if signatureSuite == SignatureSuite.ed25519Signature2020.rawValue {
            context.append("https://w3id.org/security/suites/ed25519-2020/v1")
        } else if signatureSuite == SignatureSuite.jsonWebSignature2020.rawValue {
            context.append("https://w3id.org/security/suites/jws-2020/v1")
        }
        
        guard let holder = holder else {
            throw InvalidData(message: "Holder is required for LDP VP Tokens", className: className)
        }
        
        guard let signatureSuite = signatureSuite else {
            throw InvalidData(message: "Signature suite is required for LDP VP Tokens", className: className)
        }
        
        // ccp-pilot / Digital Bazaar verify the VP's OWN proof with proofPurpose
        // "authentication" (holder binding). Without it the verifier filters our
        // proof out before signature checking — "Did not verify any proofs;
        // insufficient proofs matched the acceptable suite(s) and required
        // purpose(s)" — and returns HTTP 400. So: Ed25519Signature2020 + created +
        // verificationMethod = holder (did:jwk#0) + proofPurpose = authentication.
        let created = ISO8601DateFormatter().string(from: Date())

        let proof = Proof(
            type: signatureSuite,
            created: created,
            challenge: authorizationRequest.nonce,
            domain: authorizationRequest.clientId,
            proofPurpose: .vpProofPurpose,
            verificationMethod: holder,
            proofValue: nil
        )

        let vpTokenSigningPayload : LdpVP = .vp(
            LdpVPToken(
                context: context,
                type: ["VerifiablePresentation"],
                verifiableCredential: credentials,
                id: id,
                holder: holder,
                proof: proof
            )
        )
        
        guard let dataToSign = try? JSONEncoder().encode(vpTokenSigningPayload),
              let jsonString = String(data: dataToSign, encoding: .utf8) else {
            throw InvalidData(message: "Failed to encode LdpVPToken for signing.", className: className)
        }
        
        
        guard let jsonLdCanonicalizer = JsonLd.canonicalizer else {
            throw InvalidData(message: "Failed to get JsonLd canonicalizer.", className: className)
        }
        
        let canonicalizedData = try await jsonLdCanonicalizer(jsonString)
        let normalizedCredentialData = try Base64Decoder.decodeBase64ToData(canonicalizedData)
        
        let signatureAlgorithm: String = try await getJWSAlgorithm(from: holder)
        var signingInput = Data()
        switch signatureSuite {
        case SignatureSuite.jsonWebSignature2020.rawValue,
            SignatureSuite.ed25519Signature2018.rawValue:
            let jwsHeader = try BaseEncoding.base64URLEncode([
                "alg": signatureAlgorithm,
                // the payload is not Base64URL-encoded
                "crit" : ["b64"],
                "b64": false
            ])
            let headerBytes = Data(jwsHeader.utf8)
            let dot = Data([0x2E]) // "."
            
            signingInput.append(headerBytes)
            signingInput.append(dot)
            signingInput.append(normalizedCredentialData)
        case SignatureSuite.ed25519Signature2020.rawValue,
            SignatureSuite.rsaSignature2018.rawValue:
            signingInput.append(normalizedCredentialData)
        default:
            throw UnsupportedOperationException(message: "Unsupported signature suite: \(signatureSuite)", className: className)
        }
        
        
        let unsignedVPToken = UnsignedVPToken(
            id: identifier,
            format: .ldp_vc,
            holderKeyReference: holder,
            signatureAlgorithm: signatureAlgorithm,
            dataToSign: signingInput
        )
        
        
        return (vpTokenSigningPayload, unsignedVPToken)
    }
    
    private func extractHolderAndSignatureSuite(_ credential: AnyCodable, walletHolder: String? = nil) throws -> (holder: String, signatureSuite: String) {
        guard let credentialDict = credential.value as? [String: Any] else {
            throw InvalidData(message: "Credential is not a valid JSON object", className: className)
        }

        // Prefer the credential's own holder binding (credentialSubject.id). Bearer
        // credentials with no credentialSubject.id (e.g. veres.dev EMT) fall back to
        // the wallet holder DID supplied by the app layer, so VP construction no
        // longer fails with "Holder ID not available in the credential".
        let credentialSubject = credentialDict["credentialSubject"] as? [String: Any]
        guard let holderId = (credentialSubject?["id"] as? String) ?? walletHolder else {
            throw InvalidData(message: "Holder ID not available in the credential", className: className)
        }
        
        
        // CCP fork: sign the VP with Ed25519Signature2020 (the wallet key is Ed25519;
        // the verifier accepts Ed25519Signature2020 — JsonWebSignature2020 is not in
        // proof_type_values). Matches Android's working PDI recipe: did:jwk holder +
        // verificationMethod, Ed25519Signature2020 with a base58btc multibase
        // proofValue, and a `created` timestamp (set in buildPayloadAndUnsignedVPToken).
        return (holder: holderId, signatureSuite: SignatureSuite.ed25519Signature2020.rawValue)
    }

    private func sanitize(_ holderId: String?) -> String? {
        guard let holderId = holderId else {
            return nil
        }
        let sanitizedHolderId = holderId
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return sanitizedHolderId.contains("#") ? sanitizedHolderId : sanitizedHolderId + "#0"
    }
}
