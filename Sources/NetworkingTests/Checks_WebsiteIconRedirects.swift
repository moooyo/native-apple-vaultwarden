import Foundation
import Network
import Networking

func checkWebsiteIconRedirects(_ runner: inout TestRunner) async {
    do {
        let destination = try IconLoopbackServer { _ in "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" }
        defer { destination.stop() }
        guard let destinationPort = await destination.activePort() else {
            runner.expectTrue(false, "icons: redirect destination began listening on loopback")
            return
        }
        let origin = try IconLoopbackServer { request in
            let location = request.contains("/icons/remote.com/") ? "http://127.0.0.1:\(destinationPort.rawValue)/off-origin" : "/same-origin"
            return "HTTP/1.1 302 Found\r\nLocation: \(location)\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
        defer { origin.stop() }
        guard let originPort = await origin.activePort() else {
            runner.expectTrue(false, "icons: redirect origin began listening on loopback")
            return
        }
        let server = ServerEnvironment(string: "http://127.0.0.1:\(originPort.rawValue)")!
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [:]
        let client = WebsiteIconClient(configuration: config)
        let remote = WebsiteIconLocation(server: server, websites: ["https://remote.com"])!
        let local = WebsiteIconLocation(server: server, websites: ["https://local.com"])!
        runner.expectTrue(await client.icon(for: remote) == nil, "icons: cross-origin redirects are refused by URLSession delegate")
        runner.expectTrue(await client.icon(for: local) == nil, "icons: same-origin redirects are refused by URLSession delegate")
        runner.expect(origin.requestCount, 2, "icons: both originals reach Vaultwarden with no same-origin redirect")
        runner.expect(destination.requestCount, 0, "icons: no cross-origin request reaches the redirect destination")
        await client.invalidate()
    } catch {
        runner.expectTrue(false, "icons: loopback redirect test setup failed: \(error)")
    }
}

private final class IconLoopbackServer: @unchecked Sendable {
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
        let queue = DispatchQueue(label: "Website icon loopback fixture")
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
