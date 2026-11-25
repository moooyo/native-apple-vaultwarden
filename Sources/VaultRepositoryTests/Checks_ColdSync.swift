import AppShared
import CryptoCore
import Foundation
import Networking
import os
import UIShared
import VaultModels
import VaultRepository
import VaultStore

@MainActor
func checkColdSyncRenewsMissingBearer(_ runner: inout TestRunner) async {
    await checkColdSyncRenewsMissingBearer(&runner, usesLocalSessionStore: false)
    #if os(macOS)
    await checkColdSyncRenewsMissingBearer(&runner, usesLocalSessionStore: true)
    #endif
}

@MainActor
private func checkColdSyncRenewsMissingBearer(_ runner: inout TestRunner, usesLocalSessionStore: Bool) async {
    let session = ColdSyncTransport.makeSession()
    defer { ColdSyncTransport.close(session) }
    let keychain = makeFakeKeychain()

    do {
        let (store, directory) = try await Fixtures.freshStore()
        defer { Fixtures.cleanup(directory) }
        let initial = ServiceContainer.makeDefault(apiClient: ColdSyncTransport.makeAPI(session), store: store,
                                                   keychain: keychain, identityStore: FakeIdentityStore(),
                                                   usesLocalSessionStore: usesLocalSessionStore)
        _ = try await initial.authRepository.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        _ = try await initial.vaultRepository.sync()
        await initial.authRepository.lock()
        ColdSyncTransport.state.withLockUnchecked { $0.calls.removeAll() }

        let reopened = try VaultStore(databaseURL: directory.appendingPathComponent("vault.sqlite"),
                                      passphrase: Data("test-passphrase".utf8))
        let api = ColdSyncTransport.makeAPI(session)
        let restored = ServiceContainer.makeDefault(apiClient: api, store: reopened, keychain: keychain,
                                                    identityStore: FakeIdentityStore(), usesLocalSessionStore: usesLocalSessionStore)
        runner.expect(try await restored.authRepository.restoreSession(), Fixtures.server.base.absoluteString, "cold sync: restores the configured session")
        runner.expect(ColdSyncTransport.calls, [], "cold sync: restoration makes no HTTP requests")
        runner.expect(await api.currentAccessToken(), nil, "cold sync: the new process has no bearer")
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
        let note = PlaintextCipher(type: CipherType.secureNote.rawValue, name: "Offline note", notes: "Durable draft", secureNote: .init())
        let placeholder = try await vault.createCipher(note)
        runner.expect(try await vault.outboxStatus(for: nil).pendingCount, 1, "cold sync: an edit before the first grant is durably pending")
        runner.expect(try await vault.cipher(id: placeholder).notes, note.notes, "cold sync: the pending note is readable offline")
        runner.expect(try await restored.sendService?.listSends().isEmpty, true, "cold sync: the cached Send listing remains available before authorization")
        runner.expect(ColdSyncTransport.calls, [], "cold sync: unlocking and reading or editing the cache need no bearer or network request")

        ColdSyncTransport.state.withLockUnchecked { $0.isOffline = true }
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
        runner.expectTrue(false, "cold sync (local session: \(usesLocalSessionStore)): unexpected fixture error \(error)")
    }
}

@MainActor
func checkSyncRenewsExpiringBearer(_ runner: inout TestRunner) async {
    await checkSyncRenewsExpiringBearer(&runner, usesLocalSessionStore: false)
    #if os(macOS)
    await checkSyncRenewsExpiringBearer(&runner, usesLocalSessionStore: true)
    #endif
}

@MainActor
private func checkSyncRenewsExpiringBearer(_ runner: inout TestRunner, usesLocalSessionStore: Bool) async {
    let session = ColdSyncTransport.makeSession()
    defer { ColdSyncTransport.close(session) }
    let clock = OSAllocatedUnfairLock(initialState: ContinuousClock.now)
    let api = ColdSyncTransport.makeAPI(session, now: { clock.withLock { $0 } })

    do {
        let (store, directory) = try await Fixtures.freshStore()
        defer { Fixtures.cleanup(directory) }
        let container = ServiceContainer.makeDefault(apiClient: api, store: store, keychain: makeFakeKeychain(),
                                                     identityStore: FakeIdentityStore(), usesLocalSessionStore: usesLocalSessionStore)
        runner.expect(try await container.authRepository.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server),
                      .success, "expiring bearer: the initial grant opens the vault")
        let auth = AuthServiceAdapter(repository: container.authRepository)
        let access = VaultSyncAccess { await auth.transferSession() }
        let vault = VaultServiceAdapter(repository: container.vaultRepository, syncAccess: access)
        let model = SyncStatusModel(vault: vault)

        ColdSyncTransport.state.withLockUnchecked { $0.calls.removeAll() }
        runner.expectTrue(await model.sync(), "expiring bearer: a fresh login can sync")
        runner.expect(ColdSyncTransport.calls, [.sync], "expiring bearer: a fresh login does not renew")

        clock.withLock { $0 = $0 + .seconds(3600) }
        ColdSyncTransport.state.withLockUnchecked {
            $0.calls.removeAll()
            $0.bearer = "previous-bearer-no-longer-valid"
            $0.refreshLifetime = 60
        }
        let repository = container.vaultRepository
        let draft = PlaintextCipher(type: CipherType.secureNote.rawValue, name: "Pending after expiry", secureNote: .init())
        _ = try await repository.createCipher(draft)
        runner.expect(ColdSyncTransport.calls, [], "expiring bearer: an expired grant cannot dispatch a create")
        runner.expect(try await repository.outboxStatus().pendingCount, 1, "expiring bearer: the new item stays pending")

        async let first = repository.sync()
        async let second = repository.sync()
        _ = try await (first, second)
        let calls = ColdSyncTransport.calls
        runner.expect(calls.filter { $0 != .profile }, [.refresh, .create, .sync, .sync],
                      "expiring bearer: concurrent syncs share one renewal and dispatch the queued POST once")
        if let profile = calls.firstIndex(of: .profile), let create = calls.firstIndex(of: .create) {
            runner.expectTrue(profile < create, "expiring bearer: profile key checked before queued writes")
        } else { runner.expectTrue(false, "expiring bearer: profile and queued create must both occur") }
        runner.expect(try await repository.outboxStatus().pendingCount, 0, "expiring bearer: the upload clears the queue")

        clock.withLock { $0 = $0 + .seconds(59) }
        ColdSyncTransport.state.withLockUnchecked { $0.calls.removeAll() }
        runner.expectTrue(await model.sync(), "expiring bearer: a second renewal uses the rotated refresh token")
        runner.expect(ColdSyncTransport.calls, [.refresh, .sync],
                      "expiring bearer: sync uses the refreshed grant's shorter lifetime")

        ColdSyncTransport.state.withLockUnchecked { $0.bearer = "unexpected-server-revocation"; $0.calls.removeAll() }
        runner.expectTrue(!(await model.sync()) && access.sendListingDenied,
                          "expiring bearer: a 401 on a fresh grant still invalidates listing access")
        runner.expect(ColdSyncTransport.calls, [.sync], "expiring bearer: a genuine 401 does not replay the request")
    } catch {
        runner.expectTrue(false, "expiring bearer (local session: \(usesLocalSessionStore)): unexpected fixture error \(error)")
    }
}

@MainActor
func checkChangedAccountKeyStopsQueue(_ runner: inout TestRunner) async {
    let session = ColdSyncTransport.makeSession()
    defer { ColdSyncTransport.close(session) }
    do {
        let (store, directory) = try await Fixtures.freshStore()
        defer { Fixtures.cleanup(directory) }
        let api = ColdSyncTransport.makeAPI(session)
        let container = ServiceContainer.makeDefault(apiClient: api, store: store, keychain: makeFakeKeychain(),
                                                     identityStore: FakeIdentityStore())
        _ = try await container.authRepository.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        let accountID = await container.authRepository.session!.accountID
        ColdSyncTransport.state.withLockUnchecked { $0.isOffline = true }
        let item = PlaintextCipher(type: CipherType.secureNote.rawValue, name: "Saved offline edit", secureNote: .init())
        _ = try await container.vaultRepository.createCipher(item)
        let queued = try await store.outbox(accountID: accountID)
        runner.expect(queued.count, 1, "key change: offline edit saved before server change")
        let replacement = try SymmetricCrypto.encrypt(Data(repeating: 88, count: 64), using: Fixtures.stretchedMasterKey()).stringValue
        ColdSyncTransport.state.withLockUnchecked {
            $0.isOffline = false
            $0.profileKey = replacement
            $0.calls.removeAll()
        }
        do {
            _ = try await container.vaultRepository.sync()
            runner.expectTrue(false, "key change: changed profile must stop sync")
        } catch let error as RepositoryError {
            runner.expect(error, .reauthenticationRequired, "key change: changed profile requires signing in again")
        }
        runner.expect(ColdSyncTransport.calls, [.profile], "key change: no queued write is dispatched")
        runner.expectTrue(!(await container.authRepository.hasSession()), "key change: revoked session cannot be reused")
        runner.expect(try await store.outbox(accountID: accountID), queued, "key change: queued ciphertext was preserved")
        _ = try await container.authRepository.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        let parked = try await store.outbox(accountID: accountID)
        runner.expect(parked.first?.issue, .accountKeyChanged, "key change: a fresh login parks old encrypted changes")
        runner.expect(parked.first?.payloadJSON, queued.first?.payloadJSON, "key change: parking does not rewrite the user's edit")
    } catch { runner.expectTrue(false, "key change fixture threw: \(error)") }
}

private final class ColdSyncTransport: URLProtocol, @unchecked Sendable {
    enum Call: Equatable { case prelogin, login, refresh, profile, create, sync, unexpected }

    struct State {
        var isOffline = false
        var denySync = false
        var profileKey: String?
        var calls: [Call] = []
        var records: [Data] = []
        var bearer = "initial-fixture-bearer"
        var refreshToken = "refresh-1"
        var refreshLifetime = 3600
        var successfulRefreshes = 0
    }

    static let state = OSAllocatedUnfairLock(uncheckedState: State())
    static var calls: [Call] { state.withLockUnchecked { $0.calls } }

    static func makeSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [Self.self]
        return URLSession(configuration: configuration)
    }

    static func makeAPI(_ session: URLSession, now: @escaping @Sendable () -> ContinuousClock.Instant = { .now }) -> APIClient {
        let device = DeviceMetadata(type: DeviceMetadata.DeviceType.macOSDesktop, identifier: "cold-sync-fixture", name: "Fixture")
        return APIClient(environment: Fixtures.server, session: session, device: device, clientVersion: "2024.12.0", now: now)
    }

    static func close(_ session: URLSession) {
        session.invalidateAndCancel()
        state.withLockUnchecked { $0 = .init() }
    }

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
            var profile = ["id": "fixture-owner", "email": Fixtures.email]
            profile["key"] = state.profileKey
            switch call {
            case .prelogin: return (200, try! JSONEncoder().encode(Fixtures.prelogin()))
            case .login:
                let grant = Fixtures.tokenResponse(accessToken: state.bearer, refreshToken: state.refreshToken)
                guard let profileKey = state.profileKey else { return (200, try! JSONEncoder().encode(grant)) }
                var payload = (try! JSONSerialization.jsonObject(with: JSONEncoder().encode(grant))) as! [String: Any]
                payload["key"] = profileKey
                return Self.json(payload)
            case .refresh:
                guard form.contains("refresh_token=\(state.refreshToken)") else { return (400, Data()) }
                state.successfulRefreshes += 1
                state.bearer = "renewed-fixture-bearer-\(state.successfulRefreshes)"
                state.refreshToken = "rotated-fixture-secret-\(state.successfulRefreshes)"
                return Self.json(["access_token": state.bearer, "expires_in": state.refreshLifetime,
                                  "refresh_token": state.refreshToken, "token_type": "Bearer"])
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
