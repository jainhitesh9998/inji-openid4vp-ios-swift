import Foundation


protocol AbstractMethodsForClientIdPrefixBasedAuthorizationRequestHandler {
    func getWalletMetadata(walletConfig: WalletConfig) throws -> [String: Any]
    func isSignedRequestSupported() -> Bool
    func isUnsignedRequestSupported() throws -> Bool
    func extractPublicKey(keyId: String?, algorithm: String) async throws -> PublicKeyType
    func clientIdPrefix() -> String
    func confirmSpecVersionIdentifiedFromRequest() -> Bool
}

extension AbstractMethodsForClientIdPrefixBasedAuthorizationRequestHandler {
    func confirmSpecVersionIdentifiedFromRequest() -> Bool {
        return true
    }
}

class ClientIdPrefixBasedAuthorizationRequestHandlerBaseClass  {
    var delegate: AbstractMethodsForClientIdPrefixBasedAuthorizationRequestHandler!
    let clientId: String
    var authorizationRequestParameters: [String: Any]
    let walletConfig: WalletConfig
    let setResponseUri: (String) -> Void
    let walletNonce: String
    let networkManager: NetworkManaging
    private var specVersionHandler: SpecVersionHandler = .specV1
    var specVersion: SpecVersion = .draft23
    var shouldValidateWithWalletMetadata: Bool = false
    var className = String(describing: ClientIdPrefixBasedAuthorizationRequestHandler.self)
    
    let errorMessageForMismatchedAcceptableType: String = "does not match any acceptable types"

    /// JOSE `alg` header value that denotes an unsigned request object (RFC 7519 §6.1).
    private let unsignedRequestAlgorithm = "none"

    init(clientId: String,
         specVersion: SpecVersion,
         authorizationRequestParameters: [String: Any],
         walletConfig: WalletConfig,
         setResponseUri: @escaping (String) -> Void,
         walletNonce: String,
         networkManager: NetworkManaging = NetworkManager()) {
        self.authorizationRequestParameters = authorizationRequestParameters
        self.setResponseUri = setResponseUri
        self.networkManager = networkManager
        self.walletConfig = walletConfig
        self.walletNonce = walletNonce
        self.clientId = clientId
        self.specVersion = specVersion
    }
    
    internal func setSpecVersionHandler(_ specVersion: SpecVersion) {
        self.specVersionHandler = SpecVersionHandler.from(specVersion)
    }
    
    func handle() async throws -> AuthorizationRequest {
        try self.validateClientId()
        try await self.fetchAuthorizationRequest()
        try self.setResponseUrl()
        try await self.validateAndParseRequestFields()
        return self.createAuthorizationRequest()
    }
    
    func validateClientId() throws {
        return
    }
    
    func fetchAuthorizationRequest() async throws{
        let request = authorizationRequestParameters[AuthorizationRequestFieldConstants.request] as? String
        let requestUri = authorizationRequestParameters[AuthorizationRequestFieldConstants.requestUri] as? String
        
        if(request != nil && requestUri != nil){
            throw InvalidData(
                message: "Both 'request' and 'request_uri' cannot be present in same authorization request",
                className: className
            )
        }
        
        if let request = request {
            try await handleRequestObjectAsValue(request)
        }
        else if let requestUri = requestUri {
            try await handleRequestObjectByReference(requestUri)
        } else {
            try handleUrlEncodedRequest()
        }
        
        specVersion = findSpecVersionUsingRequestParameters(authorizationRequestParameters)
        if(!delegate.confirmSpecVersionIdentifiedFromRequest()) {
            throw InvalidData(
                message: "Spec version identification from request parameters failed",
                className: className
            )
        }
        // After fetching the VP request, populate version logic
        specVersionHandler = SpecVersionHandler.from(specVersion)
    }

    private func handleRequestObjectAsValue(_ request: String) async throws {
        try validate(request, fieldPath: AuthorizationRequestFieldConstants.request, className: className)

        self.authorizationRequestParameters = try await processRequestObject(
            request,
            deliveredVia: AuthorizationRequestFieldConstants.request,
            requestUriMethod: nil
        )
    }

    private func handleRequestObjectByReference(_ requestUri: String) async throws {
        try validate(requestUri, fieldPath: AuthorizationRequestFieldConstants.requestUri, className: className)
        guard isValidUri(requestUri)
        else {
            throw InvalidData(
                message: "request_uri \(requestUri) data is not valid",
                className: className
            )
        }
        
        let requestUriMethod : RequestUriMethod = try requestUriMethod()
        
        var body: [String: String]? = nil
        var headers: [String: String] = [Header.accept.rawValue: ContentTypes.applicationJwt.rawValue]
        
        if requestUriMethod == .post {
            body = [:]
            // wallet_nonce is a signed-request replay protection (§5.10 — echoed "in the signed
            // authorization request object"). A redirect_uri yields an unsigned request that can't
            // echo it, so don't send it (else the §5.10.1 "MUST terminate if absent" check fires).
            if delegate.isSignedRequestSupported() {
                body?[AuthorizationRequestFieldConstants.walletNonce] = walletNonce
            }
            headers[Header.contentType.rawValue] = ContentTypes.applicationFormUrlEncoded.rawValue

            try isClientIdPrefixSupported(walletConfig: walletConfig)
            
            do {
                let processedWalletMetadata = try delegate.getWalletMetadata(walletConfig: walletConfig)
                let jsonData = try JSONSerialization.data(withJSONObject: processedWalletMetadata)
                let jsonStringifiedWalletMetadata = String(data: jsonData, encoding: .utf8) ?? ""
                
                body?["wallet_metadata"] = jsonStringifiedWalletMetadata
                shouldValidateWithWalletMetadata = true
            } catch {
                OpenID4VPException.warn("Failed to process wallet metadata for POST request_uri: \(error.localizedDescription). Continuing without metadata.", className: className)
            }
        }
        var response:  NetworkResponse
        do{
            response = try await networkManager.sendHTTPRequest(url: requestUri, method: requestUriMethod.toHttpMethod(), bodyParams: body, headers: headers)
            if(!response.isOK){
                throw InvalidData(message: "Error while fetching request_uri: HTTP status code \(response.statusCode) & body: \(response.body)", className: className)
            }
        }
        catch let error as NetworkRequestException {
            let isMismatchedAcceptableType = error.localizedDescription.contains(errorMessageForMismatchedAcceptableType)
            if(isMismatchedAcceptableType){
                throw InvalidData(
                    message: "Authorization Request Object must have content type 'application/oauth-authz-req+jwt'", className: className)
            }
            throw GenericFailure(errorCode: OpenID4VPErrorCodes.invalidRequest, message: "Network error while fetching request_uri: \(error.localizedDescription)", className: className)
        } catch {
            throw GenericFailure(errorCode: OpenID4VPErrorCodes.invalidRequest, message: "Error while fetching request_uri: \(error.localizedDescription)", className: className)
        }
        self.authorizationRequestParameters = try await validateRequestUriResponse(response.body, requestUriMethod: requestUriMethod)
    }
    
    private func handleUrlEncodedRequest() throws {
        guard (try delegate.isUnsignedRequestSupported()) else {
            throw InvalidData(
                message: "unsigned request is not supported for given client_id_prefix - \(delegate.clientIdPrefix())",
                className: className
            )
        }
    }
    
    private func validateRequestUriResponse(_ requestUriResponse: String, requestUriMethod: RequestUriMethod) async throws -> [String: Any] {
        // A request object is a compact JWT that is either signed (header.payload.signature) or
        // unsigned per RFC 7519 §6.1 (header.payload with an empty signature). Anything else
        // (e.g. a plain JSON body or a JWE) is not a request object we can process.
        let componentCount = requestUriResponse.split(separator: ".").count
        guard componentCount == 2 || componentCount == 3 else {
            throw InvalidData(
                message: "Authorization Request Object must be a signed JWT", className: className)
        }

        return try await processRequestObject(
            requestUriResponse,
            deliveredVia: AuthorizationRequestFieldConstants.requestUri,
            requestUriMethod: requestUriMethod
        )
    }

    /// Obtains and validates a request object delivered by value (`request`) or by reference
    /// (`request_uri`), branching on the JOSE header `alg` instead of assuming the object is
    /// signed. An unsigned (`alg: none`) request object is accepted only for client_id_prefixes
    /// that declare unsigned support and is never signature-verified; anything else is treated as
    /// signed, accepted only for prefixes that declare signed support, and signature-verified.
    private func processRequestObject(_ requestObject: String, deliveredVia: String, requestUriMethod: RequestUriMethod?) async throws -> [String: Any] {
        let isSignedRequestObject = joseHeaderAlgorithm(of: requestObject) != unsignedRequestAlgorithm
        if !isSignedRequestObject {
            guard (try delegate.isUnsignedRequestSupported()) else {
                throw InvalidData(
                    message: "unsigned request is not supported for given client_id_prefix - \(delegate.clientIdPrefix())",
                    className: className
                )
            }
        } else {
            guard (delegate.isSignedRequestSupported()) else {
                throw InvalidData(
                    message: "Signed request (via \(deliveredVia)) is not supported for given client_id_prefix - \(delegate.clientIdPrefix())",
                    className: className
                )
            }
            try await validateJWTRequest(requestObject)
        }

        let authorizationRequestObject = try JWSHandler.extractDataJsonFromJws(jws: requestObject, jwsPart: .payload)
        // wallet_nonce is only sent + echoed for signed requests (§5.10); skip for unsigned (alg:none).
        if requestUriMethod == .post && isSignedRequestObject {
            try validateWalletNonce(authorizationRequestObject, walletNonce)
        }

        try validateAuthorizationRequestObjectAndParameters(params: authorizationRequestParameters, requestObject: authorizationRequestObject)

        return authorizationRequestObject
    }

    /// Returns the JOSE header `alg` of a compact JWT, or `nil` when the header cannot be parsed
    /// or carries no `alg`. A `nil` result is treated as signed so that `validateJWTRequest`
    /// surfaces the precise malformed-header / missing-`alg` error.
    private func joseHeaderAlgorithm(of compactJWT: String) -> String? {
        guard let header = try? JWSHandler.extractDataJsonFromJws(jws: compactJWT, jwsPart: .header) else {
            return nil
        }
        return header["alg"] as? String
    }
    
    // If the key is not associated with the client or if signature validation fails, error code = invalid_request_object
    private func validateJWTRequest(_ jwtRequest: String) async throws {
        do {
            let header:  [String : Any]
            do {
                header = try JWSHandler.extractDataJsonFromJws(jws: jwtRequest, jwsPart: .header)
            } catch {
                throw VerificationFailure(
                    message: "JWS header extraction failed: \(error.localizedDescription)",
                    className: String(describing: type(of: self))
                )
            }
            
            let typ: String? = header["typ"] as? String
            if typ != "oauth-authz-req+jwt" {
                throw InvalidData(
                    message: "Invalid typ in JWS header. Expected 'oauth-authz-req+jwt', found '\(typ ?? "nil")'",
                    className: String(describing: type(of: self)),
                    code: OpenID4VPErrorCodes.invalidRequestObject
                )
            }
            
            guard let algorithm = header["alg"] as? String else {
                throw InvalidData(message: "alg is not present in JWS header", className: className, code: OpenID4VPErrorCodes.invalidRequestObject)
            }
            
            try validateAuthorizationRequestSigningAlgorithm(algorithm)
            
            let publicKey = try await delegate.extractPublicKey(keyId: header["kid"] as? String, algorithm: algorithm)
            try await JWSHandler.verify(jws: jwtRequest , publicKey: publicKey)
        } catch {
            throw InvalidData(message: "Request URI response validation failed - \(error.localizedDescription)", className: className, code: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
    
    func validateAndParseRequestFields() async throws {
        if authorizationRequestParameters[AuthorizationRequestFieldConstants.transactionData] != nil {
            throw InvalidTransactionData(message: "Invalid Request: transaction_data is not supported in the authorization request", className: className)
        }
        try validateAttribute(AuthorizationRequestFieldConstants.responseType, values: authorizationRequestParameters)

        // missing nonce is not notified to the verifier
        try validateAttribute(AuthorizationRequestFieldConstants.nonce, values: authorizationRequestParameters, notifyVerifier: false)

        try validateResponseTypeSupported((authorizationRequestParameters[AuthorizationRequestFieldConstants.responseType] as? String)!)
        
        let optionalFields = [AuthorizationRequestFieldConstants.state, AuthorizationRequestFieldConstants.responseMode]
        for field in optionalFields {
            if (authorizationRequestParameters[field] != nil){
                try validateAttribute(field, values: authorizationRequestParameters)
            }
        }
        
        authorizationRequestParameters = try specVersionHandler.parseAndValidateClientMetadata(authorizationRequest: authorizationRequestParameters, shouldValidateWithWalletMetadata: shouldValidateWithWalletMetadata, walletConfig: walletConfig)
        
        try await specVersionHandler.validatePresentationRequest(authorizationRequestParameters: &authorizationRequestParameters,walletConfig: walletConfig, networkManager: networkManager)
    }
    
    final func setResponseUrl() throws {
        let responseMode = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode])

        // redirect_uri must not be present for direct_post / direct_post.jwt
        if responseMode == ResponseMode.directPost.rawValue || responseMode == ResponseMode.directPostJwt.rawValue {
            if authorizationRequestParameters.keys.contains(AuthorizationRequestFieldConstants.redirectUri) {
                throw InvalidData(
                    message: "\(AuthorizationRequestFieldConstants.redirectUri) should not be present for given response_mode",
                    className: className
                )
            }
        }

        try ResponseModeBasedHandlerFactory.get(responseMode: responseMode).setResponseUrl(authorizationRequestParameters: authorizationRequestParameters,setResponseUri: setResponseUri)
    }
    
    private func isClientIdPrefixSupported(walletConfig: WalletConfig) throws {
        let clientIdPrefix = delegate.clientIdPrefix()
        var walletSupportedClientIdPrefixes = walletConfig.clientIdPrefixesSupported.compactMap { $0.rawValue }
        if walletSupportedClientIdPrefixes.contains(ClientIdPrefix.decentralizedIdentifier.rawValue) {
            walletSupportedClientIdPrefixes.append(ClientIdPrefix.toClientIdScheme(.decentralizedIdentifier))
        }
        if !walletSupportedClientIdPrefixes.contains(clientIdPrefix) {
            throw InvalidData(
                message: "client_id_prefix is not supported by wallet",
                className: className
            )
        }
    }
    
    private func validateAuthorizationRequestSigningAlgorithm(_ algorithm: String) throws {
        if shouldValidateWithWalletMetadata {
            let supportedAlgs = walletConfig.requestObjectSigningAlgValuesSupported?.compactMap({$0.rawValue}) ?? []
            if !supportedAlgs.contains(algorithm) {
                throw InvalidData(
                    message: "request_object_signing_alg is not supported by wallet",
                    className: className
                )
            }
        }
    }
    
    private func requestUriMethod() throws -> RequestUriMethod {
        let requestUriMethod = authorizationRequestParameters[AuthorizationRequestFieldConstants.requestUriMethod] as? String ?? RequestUriMethod.get.rawValue
        let methodValue = requestUriMethod.lowercased()
        if methodValue == "get" {
            return .get
        } else if methodValue == "post" {
            return .post
        } else {
            throw UnsupportedHttpMethod(message: requestUriMethod, className: AuthorizationRequest.className)
        }
    }
    
    private func validateWalletNonce(_ authorizationRequestObject: [String : Any], _ walletNonce: String) throws {
        let walletNonceFromAuthorizationRequest = authorizationRequestObject[AuthorizationRequestFieldConstants.walletNonce] as? String
        if walletNonce != walletNonceFromAuthorizationRequest {
            throw InvalidData(message: "wallet_nonce provided in the authorization request is not the same as shared by wallet", className: self.className)
        }
    }
    
    final func createAuthorizationRequest() -> AuthorizationRequest {
        return specVersionHandler.getAuthorizationRequest(authorizationRequestParameters: authorizationRequestParameters)
    }
    
    private enum SpecVersionHandler {
        case specV1, draft23
        
        static func from(_ specVersion: SpecVersion) -> SpecVersionHandler {
            return specVersion == .v1 ? .specV1 : .draft23
        }

        func parseAndValidateClientMetadata(authorizationRequest: [String: Any], shouldValidateWithWalletMetadata: Bool, walletConfig: WalletConfig) throws -> [String: Any] {
            let clientMetadataHandler: ClientMetadataSpecVersionHandler = self == .draft23 ? .draft23 : .v1
            return try clientMetadataHandler.parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: shouldValidateWithWalletMetadata, walletConfig: walletConfig)
        }

        func validatePresentationRequest(authorizationRequestParameters: inout [String: Any], walletConfig: WalletConfig, networkManager: NetworkManaging) async throws {
            switch self {
            case .specV1:
                authorizationRequestParameters = try parseAndValidateDcqlQuery(authorizationRequestParameters)
                
                if let dcqlQuery = (authorizationRequestParameters[AuthorizationRequestFieldConstants.dcqlQuery]) as? DCQLQuery {
                    if dcqlQuery.credentials.contains(where: { !$0.requireCryptographicHolderBinding }) {
                        try validateAttribute(AuthorizationRequestFieldConstants.state, values: authorizationRequestParameters)
                    }
                }
                return
           case .draft23:
                authorizationRequestParameters = try await parseAndValidatePresentationDefinition(authorizationRequestParameters, walletConfig.isPresentationDefinitionUriSupported, networkManager)
            }
        }
        
        func getAuthorizationRequest(authorizationRequestParameters: [String: Any]) -> AuthorizationRequest {
            switch self {
            case .draft23:
                return AuthorizationPresentationExchangeRequest(
                    clientId: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId])!,
                    responseType: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseType])!,
                    responseMode: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode]),
                    responseUri: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri]),
                    redirectUri: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.redirectUri]),
                    nonce: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.nonce])!,
                    walletNonce: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.walletNonce]),
                    state: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.state]),
                    presentationDefinition: authorizationRequestParameters[AuthorizationRequestFieldConstants.presentationDefinition]! as! PresentationDefinition,
                    clientMetadata: authorizationRequestParameters[AuthorizationRequestFieldConstants.clientMetadata] as? ClientMetadataDraft23
                )
            case .specV1:
                return AuthorizationDcqlRequest(
                    clientId: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId])!,
                    responseType: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseType])!,
                    responseMode: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode]),
                    responseUri: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri]),
                    redirectUri: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.redirectUri]),
                    nonce: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.nonce])!,
                    walletNonce: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.walletNonce]),
                    state: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.state]),
                    dcqlQuery: authorizationRequestParameters[AuthorizationRequestFieldConstants.dcqlQuery] as! DCQLQuery,
                    clientMetadata: authorizationRequestParameters[AuthorizationRequestFieldConstants.clientMetadata] as? ClientMetadata
                )
            }
        }
    }
}

typealias ClientIdPrefixBasedAuthorizationRequestHandler = ClientIdPrefixBasedAuthorizationRequestHandlerBaseClass & AbstractMethodsForClientIdPrefixBasedAuthorizationRequestHandler
