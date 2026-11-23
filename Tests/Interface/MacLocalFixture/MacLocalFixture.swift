import AppKit
import Foundation
import Security
import VaultStore

#if !OPENVAULT_LOCAL || !OPENVAULT_LOCAL_FIXTURE
#error("MacLocalFixture must only be compiled into the standalone fixture target")
#endif

struct MacLocalFixture {
    let store: VaultStore
    let networkSession: URLSession
    let requestAllowed: @Sendable (URL) -> Bool

    init() throws {
        let interactionStatus = SecKeychainSetUserInteractionAllowed(false)
        guard interactionStatus == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(interactionStatus))
        }
        let fileManager = FileManager.default
        let directory = fileManager.temporaryDirectory
            .appendingPathComponent("openvault-fixture-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: false,
                                        attributes: [.posixPermissions: 0o700])
        do {
            let passphrase = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })
            store = try VaultStore(databaseURL: directory.appendingPathComponent("vault.sqlite"), passphrase: passphrase)
        } catch {
            try? fileManager.removeItem(at: directory)
            throw error
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCredentialStorage = nil
        configuration.connectionProxyDictionary = [:]
        networkSession = URLSession(configuration: configuration, delegate: FixtureRedirectPolicy(), delegateQueue: nil)
        let arguments = CommandLine.arguments
        let port = arguments.firstIndex(of: "--fixture-port").flatMap { index in
            arguments.dropFirst(index + 1).first.flatMap { UInt16($0) }
        }
        requestAllowed = { url in
            guard let port, port > 0 else { return false }
            return url.scheme == "http" && url.host == "127.0.0.1" && url.port == Int(port)
                && url.user == nil && url.password == nil
        }
        _ = NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification,
                                                    object: nil, queue: nil) { _ in
            try? FileManager.default.removeItem(at: directory)
        }
    }
}

private final class FixtureRedirectPolicy: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(.cancelAuthenticationChallenge, nil)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
