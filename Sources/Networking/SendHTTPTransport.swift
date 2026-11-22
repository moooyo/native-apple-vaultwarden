import Foundation

struct SendHTTPTransport {
    let session: URLSession

    func perform(_ request: URLRequest, uploading file: URL? = nil, expectsEmptyBody: Bool = false) async throws -> Data {
        guard session.configuration.identifier == nil, let expectedURL = request.url else {
            throw NetworkingError.transport("Send requires a foreground URL session")
        }
        let delegate = SendRedirectDelegate()
        let data: Data
        let response: URLResponse
        do {
            if let file {
                (data, response) = try await session.upload(for: request, fromFile: file, delegate: delegate)
            } else {
                (data, response) = try await session.data(for: request, delegate: delegate)
            }
        } catch let error as URLError {
            switch error.code {
            case .cancelled: throw CancellationError()
            case .cannotFindHost, .cannotConnectToHost, .dnsLookupFailed, .notConnectedToInternet, .timedOut:
                throw NetworkingError.serverUnreachable
            default: throw NetworkingError.transport("Send request failed")
            }
        }
        guard let http = response as? HTTPURLResponse, http.url == expectedURL else {
            throw NetworkingError.decoding("Unexpected Send response URL")
        }
        if http.statusCode == 401 { throw NetworkingError.unauthorized }
        let accepted = expectsEmptyBody ? [200, 204] : [200, 201]
        guard accepted.contains(http.statusCode) else {
            throw NetworkingError.http(status: http.statusCode, body: "Send request rejected")
        }
        guard !expectsEmptyBody || data.isEmpty else { throw NetworkingError.decoding("Expected an empty Send acknowledgment") }
        return data
    }
}

final class SendRedirectDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
