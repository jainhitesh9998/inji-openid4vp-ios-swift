import Foundation
import Alamofire

public struct NetworkResponse : Codable {
    public let statusCode: Int
    public let body: String
    public let headers: [String: String]
    
    var isOK: Bool {
        return statusCode >= StatusCodes.ok.rawValue && statusCode < StatusCodes.multipleChoices.rawValue
        
    }
}

public struct NetworkManager: NetworkManaging {
    public static var shared = NetworkManager()
    static let logTag = OpenID4VPException.getLogTag(String(describing: NetworkManager.self))
    
    public func sendHTTPRequest(
        url: String,
        method: HttpMethod,
        bodyParams requestBody: [String: String]? = nil,
        headers: [String: String]? = nil
    ) async throws -> NetworkResponse {
        NSLog("🟢OVPWIRE-REQ %@ %@ body=%@", String(describing: method), url, String(describing: requestBody))

        let requestHeaders: HTTPHeaders? = headers?.reduce(into: HTTPHeaders()) { result, header in
            result.add(name: header.key, value: header.value)
        }
        
        let contentType = headers?[Header.contentType.rawValue]
        let encoding = getEncoding(for: contentType)
        
        return try await withCheckedThrowingContinuation { continuation in
            AF.request(
                url,
                method: method,
                parameters: formatRequestBody(requestBody, for: contentType),
                encoding: encoding,
                headers: requestHeaders
            )
            .validate()
            .response { response in
                switch response.result {
                case .success:
                    if let httpResponse = response.response {
                        let responseBody: String
                        if let data = response.data, !data.isEmpty {
                            responseBody = String(data: data, encoding: .utf8) ?? ""
                        } else {
                            responseBody = ""
                        }
                        let networkResponse = NetworkResponse(
                            statusCode: httpResponse.statusCode,
                            body: responseBody,
                            headers: httpResponse.headers.dictionary
                        )
                        NSLog("🟢OVPWIRE-RESP %d %@", httpResponse.statusCode, responseBody)
                        continuation.resume(returning: networkResponse)
                    } else {
                        let exception = NetworkRequestException.invalidResponse(message: "Invalid response received")
                        OpenID4VPException.error(NetworkManager.logTag, exception)
                        continuation.resume(throwing: exception)
                    }
                case .failure(let error):
                    if let urlError = error.asAFError?.underlyingError as? URLError, urlError.code == .timedOut {
                        let exception = NetworkRequestException.networkRequestTimeout
                        OpenID4VPException.error(NetworkManager.logTag, exception)
                        continuation.resume(throwing: exception)
                        return
                    }
                    if let statusCode = response.response?.statusCode {
                        let response = NetworkResponse(
                            statusCode: statusCode,
                            body: response.data.flatMap { String(data: $0, encoding: .utf8) } ?? "",
                            headers: response.response?.headers.dictionary ?? [:]
                        )
                        continuation.resume(returning: response)
                        return
                    }
                    else {
                        let exception = NetworkRequestException.networkRequestFailed(message: "\(error.localizedDescription)")
                        OpenID4VPException.error(NetworkManager.logTag, exception)
                        continuation.resume(throwing: exception)
                    }
                }
            }
        }
    }
    
    private func getEncoding(for contentType: String?) -> ParameterEncoding {
        return URLEncoding.default
    }
    
    private func formatRequestBody(_ body: [String: String]?, for contentType: String?) -> Parameters {
        return body ?? [:]
    }
}
