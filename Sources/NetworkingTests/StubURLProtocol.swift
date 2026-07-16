import Foundation

/// A captured outgoing request (method/url/headers/body) for assertions.
struct CapturedRequest: Sendable {
    let method: String
    let url: URL
    let headers: [String: String]
    let body: Data?

    var bodyString: String { body.flatMap { String(data: $0, encoding: .utf8) } ?? "" }
    var path: String { url.path }
    func header(_ name: String) -> String? {
        // Header lookup is case-insensitive per HTTP.
        headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value
    }
}

/// The canned response a `StubURLProtocol` should return for a request.
struct StubResponse: Sendable {
    let statusCode: Int
    let body: Data
    let headers: [String: String]

    init(statusCode: Int, body: Data = Data(), headers: [String: String] = ["Content-Type": "application/json"]) {
        self.statusCode = statusCode
        self.body = body
        self.headers = headers
    }

    static func json(_ string: String, status: Int = 200) -> StubResponse {
        StubResponse(statusCode: status, body: Data(string.utf8))
    }
}

/// A thread-safe box the test and the URLProtocol share: the test sets the canned
/// response and reads back the captured request after the call completes.
final class StubBox: @unchecked Sendable {
    private let lock = NSLock()
    private let responseCondition = NSCondition()
    private var _response: StubResponse
    private var _captured: CapturedRequest?
    private var _responsesPaused = false

    init(response: StubResponse) { _response = response }

    var response: StubResponse {
        get { lock.lock(); defer { lock.unlock() }; return _response }
        set { lock.lock(); _response = newValue; lock.unlock() }
    }

    var captured: CapturedRequest? {
        get { lock.lock(); defer { lock.unlock() }; return _captured }
        set { lock.lock(); _captured = newValue; lock.unlock() }
    }

    func pauseResponses() {
        responseCondition.lock()
        _responsesPaused = true
        responseCondition.unlock()
    }

    func resumeResponses() {
        responseCondition.lock()
        _responsesPaused = false
        responseCondition.broadcast()
        responseCondition.unlock()
    }

    func waitUntilResponsesResume() {
        responseCondition.lock()
        while _responsesPaused { responseCondition.wait() }
        responseCondition.unlock()
    }
}

/// Registry mapping a routing token (carried in a custom request header) to a
/// `StubBox`. URLProtocol instances are created by the system, so requests are
/// routed to the right box via this process-wide registry. State lives in a
/// `final class` singleton behind a lock so it satisfies Swift 6 strict concurrency
/// (no mutable global `var`).
final class StubRegistry: @unchecked Sendable {
    static let shared = StubRegistry()
    private let lock = NSLock()
    private var boxes: [String: StubBox] = [:]

    func register(_ box: StubBox, token: String) {
        lock.lock(); boxes[token] = box; lock.unlock()
    }
    func box(for token: String) -> StubBox? {
        lock.lock(); defer { lock.unlock() }; return boxes[token]
    }
    func remove(token: String) {
        lock.lock(); boxes[token] = nil; lock.unlock()
    }
}

/// A `URLProtocol` that intercepts every request, captures it, and replays a canned
/// response from the `StubBox` identified by the `X-Stub-Token` header (injected via
/// the session configuration's `httpAdditionalHeaders`). This keeps the URLSession
/// fully real (so request building / header injection is exercised end-to-end)
/// while staying headless and deterministic.
final class StubURLProtocol: URLProtocol {
    static let tokenHeader = "X-Stub-Token"

    override class func canInit(with request: URLRequest) -> Bool {
        request.value(forHTTPHeaderField: tokenHeader) != nil
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let token = request.value(forHTTPHeaderField: Self.tokenHeader) ?? ""
        let box = StubRegistry.shared.box(for: token)

        // Capture the outgoing request. URLProtocol may move the body into a stream,
        // so read from httpBodyStream when httpBody is nil.
        var headers = request.allHTTPHeaderFields ?? [:]
        headers[Self.tokenHeader] = nil
        let body = request.httpBody ?? Self.readStream(request.httpBodyStream)
        box?.captured = CapturedRequest(method: request.httpMethod ?? "GET",
                                        url: request.url!,
                                        headers: headers,
                                        body: body)
        box?.waitUntilResponsesResume()

        let stub = box?.response ?? StubResponse(statusCode: 500)
        let response = HTTPURLResponse(url: request.url!,
                                       statusCode: stub.statusCode,
                                       httpVersion: "HTTP/1.1",
                                       headerFields: stub.headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: stub.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func readStream(_ stream: InputStream?) -> Data? {
        guard let stream else { return nil }
        stream.open()
        defer { stream.close() }
        var data = Data()
        let size = 4096
        var buffer = [UInt8](repeating: 0, count: size)
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: size)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
        return data
    }
}

/// Builds a `URLSession` wired to `StubURLProtocol` for a given box, plus the token
/// used to route requests. The token rides on `httpAdditionalHeaders`, so every
/// request the client makes carries it (and we strip it from captured headers).
func makeStubbedSession(box: StubBox) -> URLSession {
    let token = UUID().uuidString
    StubRegistry.shared.register(box, token: token)
    let config = URLSessionConfiguration.ephemeral
    config.protocolClasses = [StubURLProtocol.self]
    config.httpAdditionalHeaders = [StubURLProtocol.tokenHeader: token]
    return URLSession(configuration: config)
}
