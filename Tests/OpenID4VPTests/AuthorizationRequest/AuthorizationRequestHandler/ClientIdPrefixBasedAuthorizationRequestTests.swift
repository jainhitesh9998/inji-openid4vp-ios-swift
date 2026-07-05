import Foundation
import XCTest
@testable import OpenID4VP

final class ClientIdPrefixBasedAuthorizationRequestTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    var decodedClientMetadata: ClientMetadataDraft23?
    var decodedPresentationDefinition: PresentationDefinition?
    
    private var walletConfig: WalletConfig!
    
    override func setUpWithError() throws {
        walletConfig = createWalletConfig()
    }
    
    override func setUp() {
        super.setUp()
        mockNetworkManager.clearResponses()
    }
    
    ///    Fetch authorization request tests
    
    /**fetchAuthorizationRequest and spec version identification**/
    func testShouldUpdateSpecversionAsPerFullyResolvedVPRequestFor_ByValueUnsignedRequest() async {
        let authorizationRequestParametersByValue: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters), specVersion: .draft23) as [String : Any]
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByValue,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        XCTAssertEqual(mockAuthHandler.getSpecVersion(), .v1)
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest())
        XCTAssertEqual(mockAuthHandler.getSpecVersion(), .draft23)
    }
    
    func testShouldUpdateSpecversionAsPerFullyResolvedVPRequestFor_ByValueSignedRequest() async {
        let authorizationRequestParametersByValue1: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), isSigned: true, specVersion: .v1) as [String : Any]
        let mockAuthHandler1 = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByValue1,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: false
        )
        XCTAssertEqual(mockAuthHandler1.getSpecVersion(), .v1)
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler1.fetchAuthorizationRequest())
        XCTAssertEqual(mockAuthHandler1.getSpecVersion(), .v1)
        
        let authorizationRequestParametersByValue2: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), isSigned: true, specVersion: .draft23) as [String : Any]
        let mockAuthHandler2 = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByValue2,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: false
        )
        XCTAssertEqual(mockAuthHandler2.getSpecVersion(), .v1)
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler2.fetchAuthorizationRequest())
        XCTAssertEqual(mockAuthHandler2.getSpecVersion(), .draft23)
    }
    
    func testShouldUpdateSpecversionAsPerFullyResolvedVPRequestFor_ByReferenceSignedRequest() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!, ["request_uri_method": "post"]), specVersion: .v1) as [String : Any]
        let walletConfigWithoutPost = WalletConfig(
            vpFormatsSupported: walletConfig.vpFormatsSupported,
            clientIdPrefixesSupported: walletConfig.clientIdPrefixesSupported,
            requestObjectSigningAlgValuesSupported: walletConfig.requestObjectSigningAlgValuesSupported,
            authorizationEncryptionAlgValuesSupported: walletConfig.authorizationEncryptionAlgValuesSupported,
            authorizationEncryptionEncValuesSupported: walletConfig.authorizationEncryptionEncValuesSupported,
            responseTypesSupported: walletConfig.responseTypesSupported
        )
        let requestUriResponse = createRequestUriResponse(createAuthorizationRequestObject(clientIdPrefix: .decentralizedIdentifier, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), applicableFields: authRequestWithDidByValue + [AuthorizationRequestFieldConstants.walletNonce], specVersion: .draft23) )
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfigWithoutPost,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        XCTAssertEqual(mockAuthHandler.getSpecVersion(), .v1)
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest())
        XCTAssertEqual(mockAuthHandler.getSpecVersion(), .draft23)
    }
    
    func testFetchAuthoriozationRequestThrowErrorWhenSpecVersionAndRequestConformanceFails() async {
        let authorizationRequestParametersByValue: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters), specVersion: .draft23) as [String : Any]
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByValue,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        mockAuthHandler.specVersionAndVPRequestMatch = false
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error, expectedMessage: "Spec version identification from request parameters failed", expectedCode: "invalid_request")
        }
    }
    
    /** Authorization Request passed as URL with encoded params */
    
    func testShouldProceedSuccessfullyWhenAuthorizationRequestIsPassedAsUrlEncodedParams() async {
        let authorizationRequestParametersByValue: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters), specVersion: .v1) as [String : Any]
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByValue,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest())
    }
    
    func testThrowErrorWhenBothRequestAndRequestUriArePresentInAuthorizationRequest() async {
        let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(
            paramList: ["client_id", "request", "request_uri"],
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                preRegisteredSchemeClientIdParameters,
                [
                    "request": "some.signed.jwt",
                    "request_uri": "https://mock-verifier.com/verifier/get-auth-request-obj"
                ]
            ),
            specVersion: .v1
        ) as [String: Any]

        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParameters,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )

        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Both 'request' and 'request_uri' cannot be present in same authorization request",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testShouldThrowErrorWhenAuthorizationRequestByValueIsNotSupported() async {
        let authorizationRequestParametersByValue: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters)) as [String : Any]
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByValue,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: false
        )
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "unsigned request is not supported for given client_id_prefix - pre-registered",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
        
    /** Passing a request object as value **/
    
    func testShouldProceedSuccessfullyWhenAuthorizationRequestIsAvailableInRequestParamAndSignedRequestIsSupported() async {
        let authorizationRequestParametersByValue: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), isSigned: true, specVersion: .v1) as [String : Any]
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByValue,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: false
        )
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest())
    }
    
    func testShouldThrowErrorWhenClientIdIsMismatchedBetweenRequestObjectAndParameters() async {
        let authorizationRequestParametersByValue: [String : Any] = mergeMaps(
            createAuthorizationRequest(
                paramList: authRequestWithRedirectUriByValue ,
                requestParams: mergeMaps(authorizationRequestParamsWithValue), // if client id is not sent in requestparams function parameter "" is added in the signed request object
                isSigned: true, specVersion: .v1),
            DidSchemeClientIdParameters[.v1]! // attach client id in the request params to simulate the mismatch
        ) as [String : Any]
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByValue,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: false
        )
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Client Id mismatch in Authorization Request parameter and the Request Object",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShouldThrowErrorWhenRequestValueIsInvalid() async {
        let authorizationRequestParametersByValue: [String : Any] = [
            AuthorizationRequestFieldConstants.request: "",
            AuthorizationRequestFieldConstants.clientId: "mock-client-id"
        ]
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByValue,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Invalid Input: request value cannot be empty or null",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShouldThrowErrorWhenClientIdSchemeDoesNotSupportSignedRequestButInputHasSignedRequestViRequestParameter() async {
        let authorizationRequestParametersByValue: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), isSigned: true, specVersion: .v1) as [String : Any]
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByValue,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: false,
            isUnsignedRequestSupported: true
        )
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Signed request (via request) is not supported for given client_id_prefix - decentralized_identifier",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    /** Passing a request object by reference **/
    
    func testFetchAuthorizationRequestByReferenceWhenRespectiveClientIdSchemeSupportsSignedRequest() async{
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdPrefix: .decentralizedIdentifier,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!),
            applicableFields: authRequestWithRedirectUriByValue
        )
        let authorizationRequestParameters = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), specVersion: .v1) as [String : Any]
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString,responseBody: authorizationRequestObject)
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParameters,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest(), "Failed to fetch authorization request")
    }
    
    func testShouldThrowErrorWhenAuthorizationRequestIsPassedByReferenceAndSignedRequestIsNotSupported() async {
        // A signed (alg != none) request object delivered by reference for redirect_uri cannot be
        // trust-anchored, so it must still be rejected (OpenID4VP 1.0 §5.9.3).
        let signedRequestObject = createAuthorizationRequestObject(
            clientIdPrefix: .redirectUri,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter),
            applicableFields: authRequestWithRedirectUriByValue
        )
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter), specVersion: .v1) as [String : Any]
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, responseBody: signedRequestObject)
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: false,
            isUnsignedRequestSupported: true
        )

        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Signed request (via request_uri) is not supported for given client_id_prefix - redirect_uri",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testFetchAuthorizationRequestByReferenceWithUnsignedRequestObjectViaPostIsAcceptedForRedirectUri() async throws {
        mockNetworkManager.clearResponses()
        // Unsigned (alg:none) request object delivered by reference, as real redirect_uri verifiers
        // (e.g. Digital Bazaar / Veres) do with request_uri_method=post. The verifier cannot echo
        // wallet_nonce (unsigned), so the wallet must neither send nor validate it (§5.10).
        let unsignedRequestObject = try createUnsignedAuthorizationRequestObject(
            clientIdPrefix: .redirectUri,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter),
            applicableFields: authRequestWithRedirectUriByValue
        )
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter, ["request_uri_method": "post"]), specVersion: .v1) as [String : Any]
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, responseBody: unsignedRequestObject)
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: false,
            isUnsignedRequestSupported: true
        )

        await XCTAssertNoThrowAndVerifyAsync(try await mockAuthHandler.fetchAuthorizationRequest()) {
            XCTAssertEqual(mockAuthHandler.authorizationRequestParameters[AuthorizationRequestFieldConstants.responseType] as? String, "vp_token")
            XCTAssertEqual(mockAuthHandler.authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode] as? String, "direct_post")
            XCTAssertEqual(mockNetworkManager.recordedRequests[requestUri.absoluteString]?.requestMethod, .post, "Expected HTTP method to be POST")
            XCTAssertNil(mockNetworkManager.recordedRequests[requestUri.absoluteString]?.requestBody?[AuthorizationRequestFieldConstants.walletNonce], "wallet_nonce must not be sent for an unsigned (redirect_uri) request")
        }
    }

    func testFetchAuthorizationRequestByValueWithUnsignedRequestObjectIsAcceptedForRedirectUri() async throws {
        // Unsigned (alg:none) request object delivered inline via the request parameter.
        let unsignedRequestObject = try createUnsignedAuthorizationRequestObject(
            clientIdPrefix: .redirectUri,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter),
            applicableFields: authRequestWithRedirectUriByValue
        )
        let authorizationRequestParametersByValue: [String : Any] = [
            AuthorizationRequestFieldConstants.request: unsignedRequestObject,
            AuthorizationRequestFieldConstants.clientId: "redirect_uri:https://mock-verifier.com"
        ]
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByValue,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: false,
            isUnsignedRequestSupported: true
        )

        await XCTAssertNoThrowAndVerifyAsync(try await mockAuthHandler.fetchAuthorizationRequest()) {
            XCTAssertEqual(mockAuthHandler.authorizationRequestParameters[AuthorizationRequestFieldConstants.responseType] as? String, "vp_token")
            XCTAssertEqual(mockAuthHandler.authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode] as? String, "direct_post")
        }
    }

    func testShouldThrowErrorWhenUnsignedRequestObjectIsReceivedButUnsignedRequestIsNotSupported() async throws {
        // A client_id_prefix that does not support unsigned requests (e.g. decentralized_identifier)
        // must reject an unsigned request object delivered by reference.
        let unsignedRequestObject = try createUnsignedAuthorizationRequestObject(
            clientIdPrefix: .decentralizedIdentifier,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!),
            applicableFields: authRequestWithDidByValue
        )
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), specVersion: .v1) as [String : Any]
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, responseBody: unsignedRequestObject)
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: false
        )

        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "unsigned request is not supported for given client_id_prefix - decentralized_identifier",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testShouldMakeApiCallToRequestUriGetWithCorrectAcceptType() async {
        mockNetworkManager.clearResponses()
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!, ["request_uri_method": "get"])) as [String : Any]
        let requestUriResponse = createRequestUriResponse(createAuthorizationRequestObject(clientIdPrefix: .decentralizedIdentifier, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!, ["wallet_nonce": "mock-nonce"]), applicableFields: authRequestWithDidByValue + ["wallet_nonce"]), specVersion: .v1)
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest())
        
        mockNetworkManager.recordedRequests.forEach { (url, recordedRequest) in
            if (url == requestUri.absoluteString) {
                XCTAssertEqual(recordedRequest.requestMethod, HttpMethod.get, "Expected HTTP method to be POST")
                XCTAssertEqual(recordedRequest.requestHeaders?["Accept"], ContentTypes.applicationJwt.rawValue, "Expected Accept header to be \(ContentTypes.applicationJwt.rawValue)")
            }
        }
    }
    
    func testShouldMakeApiCallToRequestUriPostWithCorrectAcceptTypeAndContentTypeWhenWalletMetadataIsAvailable() async {
        mockNetworkManager.clearResponses()
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!, ["request_uri_method": "post"]), specVersion: .v1) as [String : Any]
        let requestUriResponse = createRequestUriResponse(createAuthorizationRequestObject(clientIdPrefix: .decentralizedIdentifier, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!, ["wallet_nonce": "mock-nonce"]), applicableFields: authRequestWithDidByValue + ["wallet_nonce"]) )
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest())
        
        mockNetworkManager.recordedRequests.forEach { (url, recordedRequest) in
            if (url == requestUri.absoluteString) {
                XCTAssertEqual(recordedRequest.requestMethod, HttpMethod.post, "Expected HTTP method to be POST")
                XCTAssertEqual(recordedRequest.requestHeaders?["Accept"], ContentTypes.applicationJwt.rawValue, "Expected Accept header to be \(ContentTypes.applicationJwt.rawValue)")
                XCTAssertEqual(recordedRequest.requestHeaders?["Content-Type"], ContentTypes.applicationFormUrlEncoded.rawValue, "Expected Content-Type header to be \(ContentTypes.applicationFormUrlEncoded.rawValue)")
                XCTAssertEqual(recordedRequest.requestBody?["wallet_nonce"], "mock-nonce", "Expected wallet_nonce in request body to be mock-nonce")
                XCTAssertTrue(recordedRequest.requestBody?["wallet_metadata"] != nil, "Expected wallet_metadata in request body to be present")
            }
        }
    }
    
    func testShouldMakeApiCallToRequestUriPostWithCorrectAcceptTypeAndContentTypeWhenWalletMetadataIsNotAvailable() async {
        mockNetworkManager.clearResponses()
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!, ["request_uri_method": "post"]), specVersion: .v1) as [String : Any]
        let requestUriResponse = createRequestUriResponse(createAuthorizationRequestObject(clientIdPrefix: .decentralizedIdentifier, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!, ["wallet_nonce": "mock-nonce"]), applicableFields: authRequestWithDidByValue + ["wallet_nonce"]) )
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest())
        
        mockNetworkManager.recordedRequests.forEach { (url, recordedRequest) in
            if (url == requestUri.absoluteString) {
                XCTAssertEqual(recordedRequest.requestMethod, HttpMethod.post, "Expected HTTP method to be POST")
                XCTAssertEqual(recordedRequest.requestHeaders?["Accept"], ContentTypes.applicationJwt.rawValue, "Expected Accept header to be \(ContentTypes.applicationJwt.rawValue)")
                XCTAssertEqual(recordedRequest.requestHeaders?["Content-Type"], ContentTypes.applicationFormUrlEncoded.rawValue, "Expected Content-Type header to be \(ContentTypes.applicationFormUrlEncoded.rawValue)")
                XCTAssertEqual(recordedRequest.requestBody?["wallet_nonce"], "mock-nonce", "Expected wallet_nonce in request body to be mock-nonce")
            }
        }
    }
    
    func testThrowExceptionWhenRequestUriResponseJWTHeaderExtractionFails() async {
        mockNetworkManager.clearResponses()
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!, ["request_uri_method": "post"]), specVersion: .v1) as [String : Any]
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: "eyJ0eXAiOi&vYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJzaWcta2V5MSJ9.eyJjbGllbnRfaWQiOiJtb2NrLWNsaWVudCIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSI6Imh0dHBzOi8vYTc4NzI2ODg0Y2ZmLm5ncm9rLWZyZWUuYXBwL3ZlcmlmaWVyL3ByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSIsInJlc3BvbnNlX3R5cGUiOiJ2cF90b2tlbiIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6IkVlOElGV1A5c1kxbEVrQ3VQYUorcXc9PSIsInN0YXRlIjoiYmhNUG1WYWRKTnlLYTYzVmludmdIdz09IiwicmVzcG9uc2VfdXJpIjoiaHR0cHM6Ly9hNzg3MjY4ODRjZmYubmdyb2stZnJlZS5hcHAvdmVyaWZpZXIvdnAtcmVzcG9uc2UifQ.qkdv4np_sfq86sS1f78g3BIXTBXYXe1vWE2nLESGCOGLpbOASTccVcw5l-DIDHpfbCEplMAevO5g0xwoKGh4Aw", httpUrlResponse: httpUrlResponseForJWS))
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Request URI response validation failed - JWS header extraction failed: Base64 decoding failed",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequestObject
            )
        }
    }
    
    func testThrowExceptionWhenRequestUriResponseIsNot2xx() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), specVersion: .v1) as [String : Any]
        
        let requestUriResponse = createRequestUriResponse("{\"message\" : \"Invalid request\"}", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 400, httpVersion: "", headerFields: ["Content-Type": "application/json"])!)
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Unknown error occurred Error while fetching request_uri: Error while fetching request_uri: HTTP status code 400 & body: {\"message\" : \"Invalid request\"}",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowExceptionWhenRequestUriResponseContentTypeIsNotJWT() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), specVersion: .v1) as [String : Any]
        
        let requestUriResponse = createRequestUriResponse("non-jwt", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/json"])!)
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, error: NetworkRequestException.networkRequestFailed(message: "Response does not match any acceptable types"))
        
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Authorization Request Object must have content type 'application/oauth-authz-req+jwt'",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowExceptionWhenRequestUriResponseReturnNetworkRequestException() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), specVersion: .v1) as [String : Any]
        
        let requestUriResponse = createRequestUriResponse("non-jwt", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/json"])!)
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, error: NetworkRequestException.networkRequestFailed(message: "Something went wrong"))
        
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Unknown error occurred Network error while fetching request_uri: Network request failed with error response - Something went wrong",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowExceptionWhenRequestUriResponseReturnAnyException() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), specVersion: .v1) as [String : Any]
        
        let requestUriResponse = createRequestUriResponse("non-jwt", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/json"])!)
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, error: NetworkRequestException.networkRequestFailed(message: "Something went wrong"))
        
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Unknown error occurred Network error while fetching request_uri: Network request failed with error response - Something went wrong",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowExceptionWhenRequestUriResponseIsNotJWT() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), specVersion: .v1) as [String : Any]
        
        let requestUriResponse = createRequestUriResponse("non-jwt")
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Authorization Request Object must be a signed JWT",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowExceptionWhenRequestUriResponseHasDifferentValueThanAuthorizationRequestParameters() async throws {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), specVersion: .v1) as [String : Any]
        
        let authorizationRequestObject = createAuthorizationRequestObject(clientIdPrefix: .decentralizedIdentifier, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "did:web:hacker-verifier.com"]))
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, response: (authorizationRequestObject, httpUrlResponseForJWS))
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)
        
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Client Id mismatch in Authorization Request parameter and the Request Object",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowErrorWhenWalletNonceAvailableInTheRequestUriResponseIsNotSameAsTheWalletSentNonce() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!, ["request_uri_method": "post"]), specVersion: .v1) as [String : Any]
        
        let authorizationRequestObject = createAuthorizationRequestObject(clientIdPrefix: .decentralizedIdentifier, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,DidSchemeClientIdParameters[.v1]!, [
            "wallet_nonce": "some-other-nonce",
        ]))
        let requestUriResponse = createRequestUriResponse(authorizationRequestObject)
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString,response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)
        
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "wallet_nonce provided in the authorization request is not the same as shared by wallet",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowErrorWhenPublicKeyReslutionFailedForValidatingRequestUriResponse() async throws {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), specVersion: .v1) as [String : Any]
        
        let authorizationRequestObject = createAuthorizationRequestObject(clientIdPrefix: .decentralizedIdentifier, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!))
        let requestUriResponse = createRequestUriResponse(authorizationRequestObject)
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString,response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        mockAuthHandler.setExtractPublicKeyError(error: PublicKeyResolutionFailed(
            message: "Public key extraction failed for kid: did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0",
            className: "mock"
        ))
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Request URI response validation failed - Public key extraction failed for kid: did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequestObject
            )
        }
    }
    
    func testThrowErrorWhenRequestUriResponseJWTHeaderHasInvalidTyp() async {
        let invalidTypValues: [(typ: Any?, label: String)] = [
            (typ: "jwt", label: "wrong typ value"),
            (typ: nil,   label: "missing typ")
        ]

        for (typ, label) in invalidTypValues {
            var jwsHeader: [String: Any] = ["alg": "EdDSA"]
            if let typValue = typ { jwsHeader["typ"] = typValue }
            let expectedTypInMessage = (typ as? String) ?? "nil"

            let authorizationRequestObject = createAuthorizationRequestObject(
                clientIdPrefix: .decentralizedIdentifier,
                authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!),
                jwsHeaderData: jwsHeader,
                applicableFields: authRequestWithDidByValue,
                specVersion: .v1,
                addEncryptionClientMetadataParams: false
            )
            let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(
                paramList: authRequestParamsByReference,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!),
                specVersion: .v1
            ) as [String: Any]
            mockNetworkManager.setMockResponse(for: requestUri.absoluteString, response: (responseBody: createRequestUriResponse(authorizationRequestObject).body, httpUrlResponse: createRequestUriResponse(authorizationRequestObject).httpUrlResponse))
            mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)

            let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
                authorizationRequestParameters: authorizationRequestParameters,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager,
                clientId: "mock-client-id",
                specVersion: .v1,
                walletConfig: walletConfig,
                isSignedRequestSupported: true,
                isUnsignedRequestSupported: true
            )

            await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest(), label) { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: "Request URI response validation failed - Invalid typ in JWS header. Expected 'oauth-authz-req+jwt', found '\(expectedTypInMessage)'",
                    expectedCode: OpenID4VPErrorCodes.invalidRequestObject
                )
            }
        }
    }

    func testThrowErrorWhenRequestUriReponseJWTHeaderDoesNotHaveAlgClaim() async throws {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), specVersion: .v1) as [String : Any]
        
        let jwtWithNoAlgClaim = "ewogICJ0eXAiOiAib2F1dGgtYXV0aHotcmVxK2p3dCIKfQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"
        let requestUriResponse = createRequestUriResponse(jwtWithNoAlgClaim)
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString,response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Request URI response validation failed - alg is not present in JWS header",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequestObject
            )
        }
    }
    
    func testFetchAuthoruizationRequestPopulateAuthorizationRequestFieldWithRequestUriResponseWhenAllValidationsSucceeds() async{
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdPrefix: .decentralizedIdentifier,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!),
            applicableFields: authRequestWithDidByValue, specVersion: .v1
        )
        let authorizationRequestParameters = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!)) as [String : Any]
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, responseBody: authorizationRequestObject)
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParameters,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest(), "Failed to fetch authorization request")
        
        let expected: [String: Any] = [
            "client_id": "decentralized_identifier:did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
            "response_uri": "https://mock-verifier.com",
            "dcql_query": [
                "credentials": [
                    [ "id": "cred1", "format": "dc+sd-jwt", "meta": [:]],
                    [ "id": "cred2", "format": "mso_mdoc", "meta": [:]],
                    [ "id": "cred3", "format": "ldp_vc", "meta": [:]]
                ]
            ],
            "client_metadata": [
                "encrypted_response_enc_values_supported": ["A256GCM"],
                "client_name": "Requester name",
                "jwks": [
                    "keys": [
                        [
                            "alg": "ECDH-ES",
                            "crv": "X25519",
                            "kid": "ed-key1",
                            "kty": "OKP",
                            "use": "enc",
                            "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4"
                        ],
                        [
                            "alg": "EdDSA",
                            "crv": "Ed25519",
                            "kid": "ed-key2",
                            "kty": "OKP",
                            "use": "sig",
                            "x": "5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc"
                        ]
                    ]
                ],
                "logo_uri": "https://mock-verifier.com/logo",
                "vp_formats_supported": [
                    "ldp_vp": [
                        "proof_type_values": [
                            "Ed25519Signature2018",
                            "Ed25519Signature2020"
                        ]
                    ]
                ]
            ],
            "state": "+mRQe1d6pBoJqF6Ab28klg==",
            "response_mode": "direct_post",
            "response_type": "vp_token",
            "nonce": "VbRRB/LTxLiXmVNZuyMO8A=="
        ]
        assertDictionariesEqual(expected: expected, actual: mockAuthHandler.authorizationRequestParameters)
    }
    
    
    func testFetchAuthorizationRequestByReferenceAndRequestUriMethodIsPostPassWalletMetadata() async{
        var authorizationRequestWithPostRequestUriMethod = authorizationRequestParamsWithValue
        authorizationRequestWithPostRequestUriMethod[AuthorizationRequestFieldConstants.requestUriMethod] = "post"
        
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdPrefix: .preRegistered,
            authorizationRequestParams: mergeMaps(authorizationRequestWithPostRequestUriMethod, DidSchemeClientIdParameters[.v1]!, ["wallet_nonce": "mock-nonce"]),
            applicableFields: authRequestWithRedirectUriByValue + ["wallet_nonce"], specVersion: .v1
        )
        let authorizationRequestParameters = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestWithPostRequestUriMethod, DidSchemeClientIdParameters[.v1]!)) as [String : Any]
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",responseBody: authorizationRequestObject)
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParameters,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest(), "Failed to fetch authorization request")
        
        let recordedBody = mockNetworkManager.recordedRequests["https://mock-verifier.com/verifier/get-auth-request-obj"]?.requestBody
        XCTAssertNotNil(recordedBody?["wallet_metadata"], "Expected wallet_metadata to be present in the request body")
    }
    
    func testFetchAuthorizationRequestByValueWithRequestUriMethodNotAvailableInAuthorizationRequestProvided() async{
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdPrefix: .redirectUri,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!),
            applicableFields: authRequestWithRedirectUriByValue, specVersion: .v1
        )
        let authorizationRequestParameters = createAuthorizationRequest(paramList: [AuthorizationRequestFieldConstants.clientId, "request_uri"] , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!)) as [String : Any]
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, responseBody: authorizationRequestObject)
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParameters,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        await XCTAssertNoThrowAndVerifyAsync(try await mockAuthHandler.fetchAuthorizationRequest()) {
            XCTAssertEqual(mockNetworkManager.recordedRequests[requestUri.absoluteString]?.requestMethod, .get, "Expected HTTP method to be GET when request_uri_method is not provided")
        }
    }
    
    ///   Authorization request obtained by value: gives all data as url encoded (presentation_definition is also obtained by value)
    
    func testFetchAuthorizationRequestByValue() async{
        let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue.map { $0 == "presentation_definition" ? "presentation_definition_uri" : $0 } , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter), specVersion: .v1) as [String : Any]
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParameters,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        do{
            try await mockAuthHandler.fetchAuthorizationRequest()
            
            assertDictionariesEqual(expected: [
                "state": "+mRQe1d6pBoJqF6Ab28klg==",
                "response_type": "vp_token",
                "response_uri": "https://mock-verifier.com",
                "response_mode": "direct_post",
                "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
                "client_id": "redirect_uri:https://mock-verifier.com",
                "dcql_query": [
                    "credentials": [
                        [ "id": "cred1", "format": "dc+sd-jwt", "meta": [:]],
                        [ "id": "cred2", "format": "mso_mdoc", "meta": [:]],
                        [ "id": "cred3", "format": "ldp_vc", "meta": [:]]
                    ]
                ],
                "client_metadata": [
                    "client_name": "Requester name",
                    "encrypted_response_enc_values_supported": ["A256GCM"],
                    "jwks": [
                        "keys": [
                            [
                                "kty": "OKP",
                                "crv": "X25519",
                                "use": "enc",
                                "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                                "alg": "ECDH-ES",
                                "kid": "ed-key1"
                            ],
                            [
                                "kty": "OKP",
                                "crv": "Ed25519",
                                "use": "sig",
                                "x": "5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc",
                                "alg": "EdDSA",
                                "kid": "ed-key2"
                            ]]
                    ],
                    "vp_formats_supported": [
                        "ldp_vp": [
                            "proof_type_values": ["Ed25519Signature2018", "Ed25519Signature2020"]
                        ]
                    ],
                    "logo_uri": "https://mock-verifier.com/logo"
                ],
            ], actual: mockAuthHandler.authorizationRequestParameters)
        } catch {
            XCTFail("Error should not occur but got error \(error) - \(error.localizedDescription)")
        }
    }
    
    func testFetchAuthRequestShouldThrowErrorWhenRequestUriIsNotHttpsScheme() async{
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters,["request_uri": "http://invalid-mock-verifier.com"]), specVersion: .v1) as [String : Any]
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParametersByReference,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "request_uri http://invalid-mock-verifier.com data is not valid",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
            
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestsAlgObtainedByReferenceDoesNotMatchWithWalletMetadata() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!), specVersion: .v1) as [String : Any]
        let mockSchemeAuthRequestHandler = MockClientIdPrefixAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager, clientId: didUrl, specVersion: .v1, walletConfig: walletConfig, isSignedRequestSupported: true, isUnsignedRequestSupported: true)
        mockSchemeAuthRequestHandler.shouldValidateWithWalletMetadata = true
        let requestUriResponse = createRequestUriResponse("ewogICJhbGciOiAiSFMyNTYiLAogICJ0eXAiOiAib2F1dGgtYXV0aHotcmVxK2p3dCIKfQ.eyJ10.SflK5c")
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString,response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        
        await XCTAssertAsyncThrowsError(try await mockSchemeAuthRequestHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Request URI response validation failed - request_object_signing_alg is not supported by wallet",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequestObject
            )
        }
    }
    
    func testThrowErrorWhenClientIdSchemeIsNotSupportedAsPerWalletConfig() async {
        let  minimalWalletMetadata = createWalletConfig(clientIdPrefixesSupported: [.preRegistered])
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "redirect_uri:https://federation-verifier.example.com."], ["request_uri_method": "post"])) as [String : Any]
        let mockSchemeAuthRequestHandler = MockClientIdPrefixAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager, clientId: "", specVersion: .v1, walletConfig: minimalWalletMetadata, isSignedRequestSupported: true, isUnsignedRequestSupported: true)
        mockSchemeAuthRequestHandler.shouldValidateWithWalletMetadata = true
        let requestUriResponse = createRequestUriResponse("ewogICJhbGciOiAiSFMyNTYiLAogICAgInR5cCI6ICJvYXV0aC1hdXRoei1yZXErand0Igp9.eyJ10.SflK5c")
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString,response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        
        await XCTAssertAsyncThrowsError(try await mockSchemeAuthRequestHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "client_id_prefix is not supported by wallet",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testFetchAuthRequestWithInvalidRequestUriValuesThrowError() async {
        let testCases: [TestCase<[String: Any], Void>] = [
            TestCase(
                input: ["request_uri": ""],
                expectedError: "Invalid Input: request_uri value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            ),
            TestCase(
                input: ["request_uri": "nil"],
                expectedError: "Invalid Input: request_uri value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            ),
            TestCase(
                input: ["request_uri": "null"],
                expectedError: "Invalid Input: request_uri value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(
                paramList: authRequestParamsByReference,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters, testCase.input)
            ) as [String: Any]
            
            let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
                authorizationRequestParameters: authorizationRequestParameters,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager,
                clientId: "mock-client-id",
                specVersion: .v1,
                walletConfig: walletConfig,
                isSignedRequestSupported: true,
                isUnsignedRequestSupported: true
            )
            
            await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: testCase.expectedError!,
                    expectedCode: testCase.expectedCode!
                )
            }
        }
    }
    
    
//    Fetch info for sending response (error or authorization response) to verifier
    func testResponseUrlSetSuccessfullyForResponseModeDirectPost(){
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters))  as [String : Any]
        let expectation = expectation(description: "Handler should be called with expected parameter")
        var responseUri: String?
        let mockSetResponseUri: (String) -> Void = { value in
            responseUri = value
            expectation.fulfill()
        }
        
        let clientIdPrefixBasedAuthorizationRequestHandler = ClientIdPrefixBasedAuthorizationRequestHandlerBaseClass(clientId: "mock-client", specVersion: .v1 ,authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        try? clientIdPrefixBasedAuthorizationRequestHandler.setResponseUrl()
        
        wait(for: [expectation], timeout: 2.0)
        XCTAssertEqual(responseUri, "https://mock-verifier.com", "Handler was called with unexpected parameter")
    }
    
    func testFetchInfoForSendingResponseToVerifierForInvalidResponseModeThrowInvalidResponseModeError() {
        let testCases: [TestCase<[String: String?], Void>] = [
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode: "fragment"], expectedError: "Given response_mode - fragment is not supported", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode: ""], expectedError: "Given response_mode -  is not supported", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode: "nil"], expectedError: "Given response_mode - nil is not supported", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode: "null"], expectedError: "Given response_mode - null is not supported", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode: nil], expectedError: "Given response_mode -  is not supported", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters = createAuthorizationRequest(
                paramList: authRequestWithPreRegisteredByValue,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters, testCase.input)
            ) as [String: Any]
            
            let handler = ClientIdPrefixBasedAuthorizationRequestHandlerBaseClass(clientId: "mock-client", specVersion: .v1,
                authorizationRequestParameters: authorizationRequestParameters,
                walletConfig: walletConfig,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            
            XCTAssertThrowsError(try handler.setResponseUrl()) { error in
                assertOpenID4VPException(error, expectedMessage: testCase.expectedError!, expectedCode: testCase.expectedCode!)
            }
        }
    }
    
    
    //MARK: -Validate fields in authorization request - Presentation Exchange
    
    // Spec version Draft 23 (presentation echange request is in form of DIF Presentation exchange via property - 'presentation_definition' or 'presentation_definition_uri'
    
    func testParseAndValidateAuthorizationRequestWithPresentationDefinitionByReferenceSupport() async{
        decodedClientMetadata = createInstance(clientMetadataSpecVersionDraft23, as: ClientMetadataDraft23.self)
        decodedPresentationDefinition = createInstance(presentationDefinition, as: PresentationDefinition.self)
        let presentationDefinition = convertToJsonString(presentationDefinition)
        let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue, requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter), specVersion: .draft23, isPresentationExchangeByReference: true) as [String : Any]
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/presentation-definition",responseBody: presentationDefinition)
        
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParameters,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .draft23,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        mockAuthHandler.setSpecVersionHandler(.draft23)
        do{
            try await mockAuthHandler.validateAndParseRequestFields()
            
            assertDictionariesEqual(expected: [
                "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
                "presentation_definition": decodedPresentationDefinition!,
                "response_uri": "https://mock-verifier.com",
                "state": "+mRQe1d6pBoJqF6Ab28klg==",
                "response_type": "vp_token",
                "presentation_definition_uri": "https://mock-verifier.com/presentation-definition",
                "client_metadata": decodedClientMetadata!,
                "client_id": "redirect_uri:https://mock-verifier.com",
                "response_mode": "direct_post",
            ], actual: mockAuthHandler.authorizationRequestParameters)
        } catch {
            XCTFail("Error should not occur but got error \(error) - \(error.localizedDescription)")
        }
    }
    
    func testParseAndValidateAuthorizationRequestWithPresentationDefinitionByValueSupport() async{
        decodedClientMetadata = createInstance(clientMetadataSpecVersionDraft23, as: ClientMetadataDraft23.self)
        decodedPresentationDefinition = createInstance(presentationDefinition, as: PresentationDefinition.self)
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdPrefix: .redirectUri,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter),
            applicableFields: authRequestWithRedirectUriByValue,
            specVersion: .draft23
        )
        let authorizationRequestParameters = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter), specVersion: .draft23) as [String : Any]
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",responseBody: authorizationRequestObject)
        
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParameters,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .draft23,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        mockAuthHandler.setSpecVersionHandler(.draft23)
        do{
            try await mockAuthHandler.validateAndParseRequestFields()
            
            assertDictionariesEqual(expected: [
                "client_metadata": decodedClientMetadata!,
                "response_mode": "direct_post",
                "client_id": "redirect_uri:https://mock-verifier.com",
                "response_uri": "https://mock-verifier.com",
                "presentation_definition": decodedPresentationDefinition!,
                "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
                "state": "+mRQe1d6pBoJqF6Ab28klg==",
                "response_type": "vp_token"
            ], actual: mockAuthHandler.authorizationRequestParameters)
        } catch {
            XCTFail("Error should not occur but got error \(error) - \(error.localizedDescription)")
        }
    }
    
    func testShouldThrowErrorWhenBothPresenentationDefinitionAndPresenentationDefinitionUriArePresent() async{
        let authorizationRequestParameters: [String : Any] = mergeMaps(createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter), specVersion: .draft23) as [String : Any],["presentation_definition_uri": "https://mock-verifier.com/presentation-definition", "presentation_definition": presentationDefinition])
        let clientIdPrefixBasedAuthorizationRequestHandler = ClientIdPrefixBasedAuthorizationRequestHandlerBaseClass(clientId: "mock-client",
                                                                                                     specVersion: .draft23,
                                                                                                     authorizationRequestParameters: authorizationRequestParameters,
                                                                                                     walletConfig: walletConfig,
                                                                                                     setResponseUri: mockSetResponseUri,
                                                                                                     walletNonce: "mock-nonce",
                                                                                                     networkManager: mockNetworkManager
        )
        clientIdPrefixBasedAuthorizationRequestHandler.setSpecVersionHandler(.draft23)
        await XCTAssertAsyncThrowsError(try await clientIdPrefixBasedAuthorizationRequestHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Either presentation_definition or presentation_definition_uri request param can be provided but not both",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    // end of pd testing
    
    func testInvalidRequestFieldThrowErrorForResponseTypeField() async {
        let testCases: [TestCase<[String: Any?], Void>] = [
            TestCase(input: [AuthorizationRequestFieldConstants.responseType: "null"], expectedError: "Invalid Input: response_type value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseType: ""], expectedError: "Invalid Input: response_type value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseType: "nil"], expectedError: "Invalid Input: response_type value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseType: nil], expectedError: "Missing Input: response_type param is required", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters = createAuthorizationRequest(
                paramList: authRequestWithPreRegisteredByValue,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters, testCase.input)
            ) as [String: Any]
            
            let handler = ClientIdPrefixBasedAuthorizationRequestHandlerBaseClass(
                clientId: "mock-client",
                specVersion: .v1,
                authorizationRequestParameters: authorizationRequestParameters,
                walletConfig: walletConfig,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            
            await XCTAssertAsyncThrowsError(try await handler.validateAndParseRequestFields()) { error in
                assertOpenID4VPException(error, expectedMessage: testCase.expectedError!, expectedCode: testCase.expectedCode!)
            }
        }
    }
    
    
    func testInvalidRequestFieldErrorForStateField() async {
        let testCases: [TestCase<[String: Any], Void>] = [
            TestCase(input: ["state": "null"], expectedError: "Invalid Input: state value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: ["state": ""], expectedError: "Invalid Input: state value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: ["state": "nil"], expectedError: "Invalid Input: state value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters = createAuthorizationRequest(
                paramList: authRequestWithPreRegisteredByValue,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters, testCase.input)
            ) as [String: Any]
            
            let handler = ClientIdPrefixBasedAuthorizationRequestHandlerBaseClass(
                clientId: "mock-client",
                specVersion: .v1,
                authorizationRequestParameters: authorizationRequestParameters,
                walletConfig: walletConfig,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            
            await XCTAssertAsyncThrowsError(try await handler.validateAndParseRequestFields()) { error in
                assertOpenID4VPException(error, expectedMessage: testCase.expectedError!, expectedCode: testCase.expectedCode!)
            }
        }
    }
    
    
    func testInvalidRequestFieldErrorForResponseModeField() async {
        let testCases: [TestCase<[String: Any], Void>] = [
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode: "null"], expectedError: "Invalid Input: response_mode value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode: ""], expectedError: "Invalid Input: response_mode value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode: "nil"], expectedError: "Invalid Input: response_mode value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters = createAuthorizationRequest(
                paramList: authRequestWithPreRegisteredByValue,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters, testCase.input)
            ) as [String: Any]
            
            let handler = ClientIdPrefixBasedAuthorizationRequestHandlerBaseClass(
                clientId: "mock-client",
                specVersion: .v1,
                authorizationRequestParameters: authorizationRequestParameters,
                walletConfig: walletConfig,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            
            await XCTAssertAsyncThrowsError(try await handler.validateAndParseRequestFields()) { error in
                assertOpenID4VPException(error, expectedMessage: testCase.expectedError!, expectedCode: testCase.expectedCode!)
            }
        }
    }
    
    
    func testInvalidRequestFieldErrorForNonceField() async {
        let testCases: [TestCase<[String: Any?], Void>] = [
            TestCase(input: ["nonce": "null"], expectedError: "Invalid Input: nonce value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: ["nonce": ""], expectedError: "Invalid Input: nonce value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: ["nonce": "nil"], expectedError: "Invalid Input: nonce value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: ["nonce": nil], expectedError: "Missing Input: nonce param is required", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters = createAuthorizationRequest(
                paramList: authRequestWithPreRegisteredByValue,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters, testCase.input)
            ) as [String: Any]
            
            let handler = ClientIdPrefixBasedAuthorizationRequestHandlerBaseClass(
                clientId: "mock-client",
                specVersion: .v1,
                authorizationRequestParameters: authorizationRequestParameters,
                walletConfig: walletConfig,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            
            await XCTAssertAsyncThrowsError(try await handler.validateAndParseRequestFields()) { error in
                assertOpenID4VPException(error, expectedMessage: testCase.expectedError!, expectedCode: testCase.expectedCode!)
            }
        }
    }
    
    func testShouldThrowInvalidDataErrorWhenResponseTypeInAuthorizationRequestIsNotSupported() async {
        decodedClientMetadata = createInstance(clientMetadataSpecVersionDraft23, as: ClientMetadataDraft23.self)
        decodedPresentationDefinition = createInstance(presentationDefinition, as: PresentationDefinition.self)
        let presentationDefinition = convertToJsonString(presentationDefinition)
        let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue.map { $0 == "presentation_definition" ? "presentation_definition_uri" : $0 } , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter, ["response_type": "vp_token id_token"]), specVersion: .v1) as [String : Any]
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/presentation-definition",responseBody: presentationDefinition)
        
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "response type - vp_token id_token is not supported",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShouldThrowErrorWhenInvalidClientMetadataIsProvided() async{
        let authorizationRequestParameters: [String : Any] = mergeMaps(resquestUriResponseData,["client_metadata": "{}"])
        let clientIdPrefixBasedAuthorizationRequestHandler = ClientIdPrefixBasedAuthorizationRequestHandlerBaseClass(clientId: "mock-client",
                                                                                                                     specVersion: .v1,authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce",networkManager: mockNetworkManager)
        
        clientIdPrefixBasedAuthorizationRequestHandler.setSpecVersionHandler(.v1)
        await XCTAssertAsyncThrowsError(try await clientIdPrefixBasedAuthorizationRequestHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Error during client metadata decoding - The data couldn’t be read because it is missing.",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func assertJSONStringEqual(expected: String, actual: String) {
        guard let expectedData = expected.data(using: .utf8),
              let actualData = actual.data(using: .utf8) else {
            XCTFail("Failed to convert JSON strings to Data")
            return
        }
        
        guard let expectedDict = try? JSONSerialization.jsonObject(with: expectedData, options: []) as? [String: Any],
              let actualDict = try? JSONSerialization.jsonObject(with: actualData, options: []) as? [String: Any] else {
            XCTFail("Failed to convert JSON Data to Dictionary")
            return
        }
        
        XCTAssertTrue(NSDictionary(dictionary: expectedDict).isEqual(to: actualDict), "JSONs do not match")
    }
    
    func testShouldThrowErrorWhenTransactionDataIsPresentInAuthorizationRequest() async {
        let authorizationRequestParameters: [String: Any] = mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter, [AuthorizationRequestFieldConstants.transactionData: ["foo": "bar"]])
        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParameters,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid Request: transaction_data is not supported in the authorization request",
                expectedCode: OpenID4VPErrorCodes.invalidTransactionData
            )
        }
    }
    
    // MARK: - handle method to validate and create authorization request

    func testCreateAuthorizationRequestForSpecVersionDraft23() async {
        let presentationDefinitionJson = convertToJsonString(presentationDefinition)
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdPrefix: .decentralizedIdentifier,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.draft23]!),
            applicableFields: authRequestWithRedirectUriByValue,
            specVersion: .draft23
        )
        let authorizationRequestParameters = createAuthorizationRequest(
            paramList: authRequestParamsByReference,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.draft23]!),
            specVersion: .draft23
        ) as [String: Any]
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, response: (authorizationRequestObject, httpUrlResponseForJWS))
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/presentation-definition", responseBody: presentationDefinitionJson)

        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParameters,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: didUrl,
            specVersion: .draft23,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )

        do {
            let authorizationRequest = try await mockAuthHandler.handle()
            let draft23Request = authorizationRequest as? AuthorizationPresentationExchangeRequest
            XCTAssertNotNil(draft23Request)
            XCTAssertEqual(draft23Request?.nonce, "VbRRB/LTxLiXmVNZuyMO8A==")
            XCTAssertEqual(draft23Request?.responseType, "vp_token")
            XCTAssertNotNil(draft23Request?.presentationDefinition)
        } catch {
            XCTFail("Should not throw error but got: \(error)")
        }
    }

    func testCreateAuthorizationRequestForSpecVersion1() async {
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdPrefix: .decentralizedIdentifier,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!),
            applicableFields: authRequestWithDidByValue,
            specVersion: .v1,
            addEncryptionClientMetadataParams: false
        )
        let authorizationRequestParameters = createAuthorizationRequest(
            paramList: authRequestParamsByReference,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdParameters[.v1]!),
            specVersion: .v1
        ) as [String: Any]
        mockNetworkManager.setMockResponse(for: requestUri.absoluteString, responseBody: authorizationRequestObject)
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)

        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParameters,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "mock-client-id",
            specVersion: .v1,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )

        do {
            let authorizationRequest = try await mockAuthHandler.handle()
            let v1Request = authorizationRequest as? AuthorizationDcqlRequest
            XCTAssertNotNil(v1Request)
            XCTAssertEqual(v1Request?.nonce, "VbRRB/LTxLiXmVNZuyMO8A==")
            XCTAssertEqual(v1Request?.responseType, "vp_token")
        } catch {
            XCTFail("Should not throw error but got: \(error)")
        }
    }

    // MARK: - Version specific logic tests

    func testDraft23ThrowsErrorForInvalidPresentationDefinitionInRequestObject() async {
        let authorizationRequestParameters = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter, ["id": "vp_presentation_definition"]),
            specVersion: .draft23,
            addEncryptionClientMetadataParams: false
        ) as [String: Any]

        let mockAuthHandler = MockClientIdPrefixAuthRequestHandler(
            authorizationRequestParameters: authorizationRequestParameters,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager,
            clientId: "redirect_uri:https://mock-verifier.com",
            specVersion: .draft23,
            walletConfig: walletConfig,
            isSignedRequestSupported: true,
            isUnsignedRequestSupported: true
        )
        mockAuthHandler.setErrorToBeThrown(error: InvalidData(message: "Error during presentation definition decoding - The data couldn’t be read because it is missing.", className: "Test", code: OpenID4VPErrorCodes.invalidRequest))

        await XCTAssertAsyncThrowsError(try await mockAuthHandler.handle()) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Error during presentation definition decoding - The data couldn’t be read because it is missing.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testSpecVersion1ThrowsErrorWheAtleastOneCredentialQueryHasNoCryptographicBindingRequestButHasNoState() async {
        let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(
            paramList: authRequestWithPreRegisteredByValue,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters, [
                "state": nil,
                "dcql_query": [
                    "credentials": [
                        [ "id": "cred1", "format": "dc+sd-jwt", "meta": [:], "require_cryptographic_holder_binding": false],
                        [ "id": "cred2", "format": "mso_mdoc", "meta": [:]],
                        [ "id": "cred3", "format": "ldp_vc", "meta": [:]]
                    ]
                ]]),
            specVersion: .v1,
            addEncryptionClientMetadataParams: false
        ) as [String: Any]

        let handler = ClientIdPrefixBasedAuthorizationRequestHandlerBaseClass(
            clientId: "mock-client",
            specVersion: .v1,
            authorizationRequestParameters: authorizationRequestParameters,
            walletConfig: walletConfig,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        handler.setSpecVersionHandler(.v1)

        await XCTAssertAsyncThrowsError(try await handler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Missing Input: state param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testSpecVersion1ThrowsErrorWhenDcqlQueryHasInvalidCredentialQueryId() async {
        let invalidDcqlQuery: [String: Any] = [
            "credentials": [
                ["id": "invalid id!", "format": "dc+sd-jwt", "meta": [:]]
            ]
        ]
        let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(
            paramList: authRequestWithPreRegisteredByValue,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters, ["dcql_query": invalidDcqlQuery]),
            specVersion: .v1,
            addEncryptionClientMetadataParams: false
        ) as [String: Any]

        let handler = ClientIdPrefixBasedAuthorizationRequestHandlerBaseClass(
            clientId: "mock-client",
            specVersion: .v1,
            authorizationRequestParameters: authorizationRequestParameters,
            walletConfig: walletConfig,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        handler.setSpecVersionHandler(.v1)

        await XCTAssertAsyncThrowsError(try await handler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Credential Query id must consist of alphanumeric, underscore or hyphen characters",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testSpecVersion1PassesWhenDirectPostResponseModeHasNonce() async {
        let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(
            paramList: authRequestWithPreRegisteredByValue,
            requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdParameters),
            specVersion: .v1,
            addEncryptionClientMetadataParams: false
        ) as [String: Any]

        let handler = ClientIdPrefixBasedAuthorizationRequestHandlerBaseClass(
            clientId: "mock-client",
            specVersion: .v1,
            authorizationRequestParameters: authorizationRequestParameters,
            walletConfig: walletConfig,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        handler.setSpecVersionHandler(.v1)

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }

    func testDraft23ThrowsErrorForInvalidClientMetadataInRequestObject() async {
        let authorizationRequestParameters: [String: Any] = mergeMaps(resquestUriResponseData, ["client_metadata": "{}"])

        let handler = ClientIdPrefixBasedAuthorizationRequestHandlerBaseClass(
            clientId: "mock-client",
            specVersion: .draft23,
            authorizationRequestParameters: authorizationRequestParameters,
            walletConfig: walletConfig,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        handler.setSpecVersionHandler(.draft23)

        await XCTAssertAsyncThrowsError(try await handler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Error during client metadata decoding - Missing Input: client_metadata->vp_formats param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testSpecVersion1ThrowsErrorForInvalidClientMetadataInRequestObject() async {
        let authorizationRequestParameters: [String: Any] = mergeMaps(resquestUriResponseData, ["client_metadata": "{}"])

        let handler = ClientIdPrefixBasedAuthorizationRequestHandlerBaseClass(
            clientId: "mock-client",
            specVersion: .v1,
            authorizationRequestParameters: authorizationRequestParameters,
            walletConfig: walletConfig,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        handler.setSpecVersionHandler(.v1)

        await XCTAssertAsyncThrowsError(try await handler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Error during client metadata decoding - The data couldn’t be read because it is missing.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
