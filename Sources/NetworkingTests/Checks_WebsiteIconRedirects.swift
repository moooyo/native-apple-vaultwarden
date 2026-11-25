import Foundation
import Network
import Networking

#if os(macOS)
func checkLoopbackRedirects(_ runner: inout TestRunner) async {
    do {
        let destination = try TransportLoopbackServer { _ in "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" }
        defer { destination.stop() }
        guard let destinationPort = await destination.activePort() else {
            runner.expectTrue(false, "transport: redirect destination began listening on loopback")
            return
        }
        let origin = try TransportLoopbackServer { request in
            let offOrigin = request.contains("/icons/remote.com/") || request.hasPrefix("POST /proxy/identity/connect/token ")
            let location = offOrigin ? "http://127.0.0.1:\(destinationPort.rawValue)/off-origin" : "/same-origin"
            return "HTTP/1.1 307 Temporary Redirect\r\nLocation: \(location)\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
        defer { origin.stop() }
        guard let originPort = await origin.activePort() else {
            runner.expectTrue(false, "transport: redirect origin began listening on loopback")
            return
        }
        let server = ServerEnvironment(string: "http://127.0.0.1:\(originPort.rawValue)/proxy")!
        let unbound = ServerEnvironment(string: "http://127.0.0.1:\(destinationPort.rawValue)/proxy")!
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [:]
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }
        let policy: @Sendable (URL) -> Bool = { $0.scheme == "http" && $0.host == "127.0.0.1" && $0.port == Int(originPort.rawValue) }
        let defaultAPI = APIClient(environment: server, session: session, device: Fixtures.device,
                                   clientVersion: Fixtures.clientVersion)
        let fixtureAPI = APIClient(environment: server, session: session, device: Fixtures.device,
                                   clientVersion: Fixtures.clientVersion, requestAllowed: policy)
        let remote = WebsiteIconLocation(server: server, websites: ["https://remote.com"])!
        let local = WebsiteIconLocation(server: server, websites: ["https://local.com"])!
        let defaultIcons = WebsiteIconClient(configuration: config)
        let icons = WebsiteIconClient(configuration: config, requestAllowed: policy)

        let denial = NetworkingError.transport("The request destination is not allowed")
        await runner.expectThrowsErrorAsync(denial, "transport: HTTP loopback without explicit fixture opt-in is denied") {
            _ = try await defaultAPI.prelogin(email: "fixture@example.test")
        }
        await runner.expectThrowsErrorAsync(denial, "transport: opt-in is limited to the bound fixture port") {
            _ = try await fixtureAPI.prelogin(email: "fixture@example.test", server: unbound)
        }
        runner.expectTrue(await defaultIcons.icon(for: local) == nil, "icons: default transport refuses cleartext loopback")
        runner.expect(origin.requestCount, 0, "transport: no default cleartext traffic reaches the fixture")

        let redirect = NetworkingError.http(status: 307, body: "Redirects are not allowed")
        await runner.expectThrowsErrorAsync(redirect, "transport: password grants refuse cross-origin redirects in URLSession") {
            _ = try await fixtureAPI.token(email: "fixture@example.test", passwordHash: "synthetic-hash")
        }
        await fixtureAPI.setAccessToken("synthetic-bearer")
        await runner.expectThrowsErrorAsync(redirect, "transport: authenticated API requests refuse even same-origin redirects") {
            _ = try await fixtureAPI.sync()
        }
        runner.expectTrue(await icons.icon(for: remote) == nil, "icons: cross-origin redirects are refused by URLSession delegate")
        runner.expectTrue(await icons.icon(for: local) == nil, "icons: same-origin redirects are refused by URLSession delegate")
        runner.expect(origin.requestCount, 4, "transport: only original requests hit the bound fixture and none were replayed")
        runner.expect(destination.requestCount, 0, "transport: no request reaches an unbound redirect destination")
        await defaultIcons.invalidate()
        await icons.invalidate()
    } catch {
        runner.expectTrue(false, "transport: loopback redirect test setup failed: \(error)")
    }
}

private final class TransportLoopbackServer: @unchecked Sendable {
    private enum State { case starting, listening(NWEndpoint.Port), stopped }

    private let listener: NWListener
    private let lock = NSLock()
    private var state = State.starting
    private var count = 0

    var requestCount: Int { lock.withLock { count } }

    init(response: @escaping @Sendable (String) -> String) throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
        let queue = DispatchQueue(label: "Transport loopback fixture")
        listener.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            self.lock.withLock {
                switch state {
                case .ready:
                    if let port = self.listener.port { self.state = .listening(port) }
                case .failed, .cancelled:
                    self.state = .stopped
                default:
                    break
                }
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { connection.cancel(); return }
            self.lock.withLock { self.count += 1 }
            connection.start(queue: queue)
            Self.receive(connection, buffered: Data(), response: response)
        }
        listener.start(queue: queue)
    }

    func activePort() async -> NWEndpoint.Port? {
        let deadline = ContinuousClock.now + .seconds(3)
        while ContinuousClock.now < deadline {
            switch lock.withLock({ state }) {
            case .listening(let port): return port
            case .stopped: return nil
            case .starting: try? await Task.sleep(for: .milliseconds(10))
            }
        }
        return nil
    }

    func stop() {
        listener.cancel()
    }

    private static func receive(_ connection: NWConnection, buffered: Data, response: @escaping @Sendable (String) -> String) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, complete, error in
            let request = buffered + (data ?? Data())
            if let header = String(data: request, encoding: .utf8), header.contains("\r\n\r\n") {
                connection.send(content: Data(response(header).utf8), completion: .contentProcessed { _ in connection.cancel() })
            } else if !complete, error == nil, request.count < 4096 {
                receive(connection, buffered: request, response: response)
            } else {
                connection.cancel()
            }
        }
    }
}
#endif
