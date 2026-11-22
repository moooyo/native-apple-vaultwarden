import AppShared
import Foundation
import Networking
import os
import UIShared
import VaultModels
import VaultRepository
import VaultStore

@MainActor
func checkColdSyncRenewsMissingBearer(_ runner: inout TestRunner) async {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [ColdSyncTransport.self]
    let session = URLSession(configuration: configuration)
    defer {
        session.invalidateAndCancel()
        ColdSyncTransport.state.withLockUnchecked { $0 = .init() }
    }
    let keychain = makeFakeKeychain()
    let device = DeviceMetadata(type: DeviceMetadata.DeviceType.macOSDesktop, identifier: "cold-sync-fixture", name: "Fixture")
    func makeAPI() -> APIClient {
        APIClient(environment: Fixtures.server, session: session, device: device, clientVersion: "2024.12.0")
    }

    do {
        let (store, directory) = try await Fixtures.freshStore()
        defer { Fixtures.cleanup(directory) }
        let initial = ServiceContainer.makeDefault(apiClient: makeAPI(), store: store, keychain: keychain,
                                                   identityStore: FakeIdentityStore())
        _ = try await initial.authRepository.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        _ = try await initial.vaultRepository.sync()
        ColdSyncTransport.state.withLockUnchecked { $0.isOffline = true; $0.calls.removeAll() }
        let note = PlaintextCipher(type: CipherType.secureNote.rawValue, name: "Offline note", notes: "Durable draft", secureNote: .init())
        let placeholder = try await initial.vaultRepository.createCipher(note)
        runner.expect(try await initial.vaultRepository.outboxStatus().pendingCount, 1, "cold sync: an offline write is durably pending")
        runner.expect(ColdSyncTransport.state.withLockUnchecked { $0.records.count }, 0, "cold sync: the disconnected server received no write")

        let reopened = try VaultStore(databaseURL: directory.appendingPathComponent("vault.sqlite"),
                                       passphrase: Data("test-passphrase".utf8))
        let api = makeAPI()
        let restored = ServiceContainer.makeDefault(apiClient: api, store: reopened, keychain: keychain,
                                                    identityStore: FakeIdentityStore())
        runner.expect(try await restored.authRepository.restoreSession(), Fixtures.server.base.absoluteString, "cold sync: restores the configured session")
        runner.expect(try? await restored.authRepository.refresh(), nil, "cold sync: the startup refresh fails while disconnected")
        runner.expect(await api.currentAccessToken(), nil, "cold sync: the new process has no bearer")
        ColdSyncTransport.state.withLockUnchecked { $0.calls.removeAll() }
        do {
            _ = try await restored.vaultRepository.sync()
            runner.expectTrue(false, "cold sync: a locked vault must not synchronize")
        } catch RepositoryError.locked {
            runner.expect(ColdSyncTransport.state.withLockUnchecked { $0.calls }, [],
                          "cold sync: locked sync does not send a refresh or a vault request")
        }
        let auth = AuthServiceAdapter(repository: restored.authRepository)
        try await auth.unlockWithMasterPassword(Fixtures.password)
        let access = VaultSyncAccess { await auth.transferSession() }
        let vault = VaultServiceAdapter(repository: restored.vaultRepository, syncAccess: access)
        let model = SyncStatusModel(vault: vault)
        runner.expect(try await vault.cipher(id: placeholder).notes, note.notes, "cold sync: offline unlock decrypts the pending note in the reopened store")

        ColdSyncTransport.state.withLockUnchecked { $0.calls.removeAll() }
        runner.expectTrue(!(await model.sync()), "cold sync: a disconnected manual sync reports failure")
        runner.expect(ColdSyncTransport.state.withLockUnchecked { $0.calls }, [.refresh], "cold sync: a failed renewal does not send unauthenticated vault traffic")
        runner.expect(model.outboxStatus.pendingCount, 1, "cold sync: failed renewal preserves the queue")
        runner.expectTrue(model.outboxStatus.issues.isEmpty && !access.sendListingDenied, "cold sync: offline is neither a conflict nor access denial")

        ColdSyncTransport.state.withLockUnchecked { $0.isOffline = false; $0.calls.removeAll() }
        runner.expectTrue(await model.sync(), "cold sync: first retry succeeds after reconnecting in the same process")
        runner.expect(ColdSyncTransport.state.withLockUnchecked { $0.calls }, [.refresh, .profile, .create, .sync],
                      "cold sync: restores authorization before resolving the owner, uploading once, and pulling")
        runner.expect(ColdSyncTransport.state.withLockUnchecked { $0.records.count }, 1, "cold sync: the server received exactly one item")
        runner.expectTrue(!model.hasOutstandingChanges && model.errorMessage == nil && model.lastSync != nil,
                          "cold sync: the model reports success with an empty queue")
        runner.expect(try await vault.ciphers().map(\.id), ["reconnected-item-1"], "cold sync: the pull replaced the optimistic row instead of duplicating it")
        runner.expect(try await vault.cipher(id: placeholder).notes, note.notes, "cold sync: the pending item's alias resolves to its unchanged content")

        ColdSyncTransport.state.withLockUnchecked { $0.calls.removeAll() }
        runner.expectTrue(await model.sync(), "cold sync: a second sync succeeds with the existing bearer")
        runner.expect(ColdSyncTransport.state.withLockUnchecked { $0.calls }, [.sync], "cold sync: no redundant refresh or second upload after recovery")

        ColdSyncTransport.state.withLockUnchecked { $0.denySync = true; $0.calls.removeAll() }
        runner.expectTrue(!(await model.sync()) && access.sendListingDenied, "cold sync: an authenticated 403 is still an access denial")
        runner.expect(ColdSyncTransport.state.withLockUnchecked { $0.calls }, [.sync], "cold sync: a 403 does not renew authorization or retry")
    } catch {
        runner.expectTrue(false, "cold sync: unexpected fixture error \(error)")
    }
}

private final class ColdSyncTransport: URLProtocol, @unchecked Sendable {
    enum Call: Equatable { case prelogin, login, refresh, profile, create, sync, unexpected }

    struct State {
        var isOffline = false
        var denySync = false
        var calls: [Call] = []
        var records: [Data] = []
        var bearer = "initial-fixture-bearer"
    }

    static let state = OSAllocatedUnfairLock(uncheckedState: State())

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url, url.host == Fixtures.server.base.host else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL)); return
        }
        let body = request.httpBody ?? Self.readBody(request.httpBodyStream)
        let form = String(decoding: body, as: UTF8.self).split(separator: "&")
        let call: Call = switch (request.httpMethod, url.path) {
        case ("POST", "/identity/accounts/prelogin"): .prelogin
        case ("POST", "/identity/connect/token") where form.contains("grant_type=password"): .login
        case ("POST", "/identity/connect/token") where form.contains("grant_type=refresh_token"): .refresh
        case ("GET", "/api/accounts/profile"): .profile
        case ("POST", "/api/ciphers"): .create
        case ("GET", "/api/sync"): .sync
        default: .unexpected
        }
        let result = Self.state.withLockUnchecked { state -> (status: Int, data: Data)? in
            state.calls.append(call)
            guard !state.isOffline else { return nil }
            let profile = ["id": "fixture-owner", "email": Fixtures.email]
            switch call {
            case .prelogin: return (200, try! JSONEncoder().encode(Fixtures.prelogin()))
            case .login: return (200, try! JSONEncoder().encode(Fixtures.tokenResponse(accessToken: state.bearer)))
            case .refresh:
                guard form.contains("refresh_token=refresh-1") else { return (400, Data()) }
                state.bearer = "renewed-fixture-bearer"
                return Self.json(["access_token": state.bearer, "expires_in": 3600, "token_type": "Bearer"])
            default:
                guard request.value(forHTTPHeaderField: "Authorization") == "Bearer \(state.bearer)" else { return (401, Data()) }
            }
            switch call {
            case .profile: return Self.json(profile)
            case .create:
                guard var record = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any],
                      record["encryptedFor"] as? String == profile["id"] else { return (422, Data()) }
                record["id"] = "reconnected-item-\(state.records.count + 1)"
                record["revisionDate"] = "2026-11-23T00:00:00Z"
                let response = Self.json(record)
                if response.0 == 200 { state.records.append(response.1) }
                return response
            case .sync:
                guard !state.denySync else { return (403, Data()) }
                let records = state.records.compactMap { try? JSONSerialization.jsonObject(with: $0) }
                return Self.json(["profile": profile, "folders": [], "ciphers": records, "sends": []])
            default: return (404, Data())
            }
        }
        guard let result else {
            client?.urlProtocol(self, didFailWithError: URLError(.cannotConnectToHost)); return
        }
        let response = HTTPURLResponse(url: url, statusCode: result.status, httpVersion: "HTTP/1.1",
                                       headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: result.data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func json(_ object: Any) -> (Int, Data) {
        guard let data = try? JSONSerialization.data(withJSONObject: object) else { return (500, Data()) }
        return (200, data)
    }

    private static func readBody(_ stream: InputStream?) -> Data {
        guard let stream else { return Data() }
        stream.open()
        defer { stream.close() }
        var bytes = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let length = stream.read(&buffer, maxLength: buffer.count)
            guard length > 0 else { return bytes }
            bytes.append(buffer, count: length)
        }
    }
}
