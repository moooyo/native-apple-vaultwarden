import Foundation

/// The only cleartext exception is the Mac fixture's explicitly allowed IPv4 loopback port.
/// The injected predicate can narrow HTTPS destinations, but cannot enable other HTTP hosts.
struct TransportDestinationPolicy: Sendable {
    static let denied = NetworkingError.transport("The request destination is not allowed")

    let requestAllowed: (@Sendable (URL) -> Bool)?

    func allows(_ url: URL) -> Bool {
        guard let origin = HTTPOrigin(url) else { return false }
        if origin.scheme == "https" { return requestAllowed?(url) ?? true }
        #if os(macOS)
        return origin.host == "127.0.0.1" && url.port != nil && requestAllowed?(url) == true
        #else
        return false
        #endif
    }

    func allows(_ server: ServerEnvironment) -> Bool {
        [server.base, server.identityURL, server.apiURL].compactMap { $0 }.allSatisfy {
            $0.query == nil && allows($0)
        }
    }
}

/// Web origin, with the default port made explicit. Userinfo and fragments are not request destinations.
struct HTTPOrigin: Equatable {
    let scheme: String
    let host: String
    private let port: Int

    init?(_ url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(), scheme == "https" || scheme == "http",
              let host = components.percentEncodedHost?.lowercased(), !host.isEmpty,
              components.percentEncodedUser == nil, components.percentEncodedPassword == nil,
              components.percentEncodedFragment == nil else { return nil }

        if let port = components.port, (1...65535).contains(port) {
            self.port = port
        } else if components.rangeOfPort == nil {
            port = scheme == "https" ? 443 : 80
        } else {
            return nil
        }
        self.scheme = scheme
        self.host = host
    }
}

/// Never let URLSession replay a request or forward its body, bearer, or metadata to a redirect.
final class DirectHTTPDelegate: NSObject, URLSessionDataDelegate {
    static let shared = DirectHTTPDelegate()

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, willCacheResponse response: CachedURLResponse,
                    completionHandler: @escaping @Sendable (CachedURLResponse?) -> Void) {
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(Self.disposition(for: challenge), nil)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(Self.disposition(for: challenge), nil)
    }

    private static func disposition(for challenge: URLAuthenticationChallenge) -> URLSession.AuthChallengeDisposition {
        challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust
            ? .performDefaultHandling : .cancelAuthenticationChallenge
    }
}
