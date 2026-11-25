#if os(macOS)
import AppShared
import Foundation
import KeyVault
import KeychainBridge
import Networking
import SyncEngine
import VaultModels
import VaultRepository
import VaultStore

func checkStandaloneVaultSession(_ runner: inout TestRunner) async {
    let server = ServerEnvironment(string: "https://vault.example.test/acceptance")!
    let equivalentServer = ServerEnvironment(string: "https://VAULT.EXAMPLE.TEST:443/acceptance/")!
    let otherServer = ServerEnvironment(string: "https://vault.example.test/other")!
    let accountID = "https://vault.example.test/acceptance|\(Fixtures.email)"
    let initialRefresh = "standalone-fixture-initial"
    let rotatedRefresh = "standalone-fixture-rotated"
    let existingMarkers = legacyLocalVaultMarkers(accountID: accountID)
    let spy = LocalVaultKeychainSpy(items: existingMarkers)
    let keychain = KeychainBridge(localMacService: "local-session-fixture", itemStore: spy)

    do {
        let (store, directory) = try await Fixtures.freshStore()
        defer { Fixtures.cleanup(directory) }
        let original = makeLocalVaultHarness(store: store, keychain: keychain,
                                             tokenResults: [.success(Fixtures.tokenResponse(refreshToken: initialRefresh))])
        try await store.upsertAccounts([AccountRow(id: accountID, email: Fixtures.email, serverURL: server.base.absoluteString,
                                                   kdfType: 0, kdfIters: Fixtures.iterations,
                                                   encUserKey: Fixtures.protectedUserKeyWire())])
        runner.expect(try await original.auth.restoreSession(), nil,
                      "standalone session: a valid legacy marker and cached account cannot restore without a SQL session")
        runner.expectTrue(!(await original.keyVault.isUnlocked) && !spy.wasAccessed,
                          "standalone session: no legacy Keychain item was consulted")

        runner.expect(try await original.auth.login(email: Fixtures.email, password: Fixtures.password, server: server), .success,
                      "standalone session: explicit sign-in installs the new session")
        runner.expect(await original.auth.session?.accountID, accountID, "standalone session: sign-in uses the canonical account ID")
        let savedSession = try await store.localVaultSession()
        runner.expect(savedSession?.accountID, accountID, "standalone session: the SQL session owns the canonical cache")
        runner.expectTrue(savedSession?.refreshToken == initialRefresh && savedSession?.localAuthHash.isEmpty == false,
                          "standalone session: the SQL row contains the refresh secret and local verifier")

        let saved = PlaintextCipher(type: CipherType.secureNote.rawValue, name: "Standalone cache fixture",
                                    notes: "A confirmed record", secureNote: .init())
        let savedID = try await original.vault.createCipher(saved)
        await original.api.setCreateError(NetworkingError.serverUnreachable)
        let draft = PlaintextCipher(type: CipherType.secureNote.rawValue, name: "Standalone outbox fixture",
                                     notes: "An offline write", secureNote: .init())
        let draftID = try await original.vault.createCipher(draft)
        let waiting = try await store.outbox(accountID: accountID)
        runner.expect(waiting.map(\.entityID), [draftID], "standalone session: the offline draft owns one durable outbox row")
        runner.expect(try await original.vault.outboxStatus().pendingCount, 1, "standalone session: the row is ready to retry")
        await original.auth.lock()

        let reopenedStore = try reopenLocalVaultStore(in: directory)
        let input = URLSessionConfiguration.ephemeral
        input.protocolClasses = [LocalVaultNoNetwork.self]
        let session = URLSession(configuration: input)
        LocalVaultNoNetwork.reset()
        defer {
            session.invalidateAndCancel()
            LocalVaultNoNetwork.reset()
        }
        let device = DeviceMetadata(type: DeviceMetadata.DeviceType.macOSDesktop, identifier: "local-session-fixture", name: "Fixture")
        let apiClient = APIClient(environment: otherServer, session: session, device: device, clientVersion: "2024.12.0")
        let reopened = ServiceContainer.makeDefault(apiClient: apiClient, store: reopenedStore, keychain: keychain,
                                                     identityStore: FakeIdentityStore(), usesLocalSessionStore: true)
        runner.expect(try await reopened.authRepository.restoreSession(), server.base.absoluteString,
                      "standalone session: the production container restores the persisted deployment")
        runner.expect(await reopened.authRepository.session?.accountID, accountID, "standalone session: cold restoration binds the same account")
        runner.expectTrue(!(await reopened.keyVault.isUnlocked), "standalone session: cold restoration does not load the user key")
        runner.expect(await apiClient.currentAccessToken(), nil, "standalone session: cold restoration does not load a bearer")
        await runner.expectThrowsErrorAsync(RepositoryError.authenticationFailed, "standalone session: wrong master password is rejected offline") {
            try await reopened.authRepository.unlockWithMasterPassword("wrong-fixture-master-password")
        }
        runner.expectTrue(!(await reopened.keyVault.isUnlocked), "standalone session: rejection leaves the vault locked")
        try await reopened.authRepository.unlockWithMasterPassword(Fixtures.password)
        runner.expect(try await reopened.vaultRepository.cipher(id: savedID).notes, saved.notes,
                      "standalone session: offline unlock decrypts the original confirmed record")
        runner.expect(try await reopened.vaultRepository.cipher(id: draftID).notes, draft.notes,
                      "standalone session: offline unlock decrypts the pending optimistic record")
        runner.expectTrue(try await reopenedStore.outbox(accountID: accountID) == waiting,
                          "standalone session: cold unlock leaves the exact pending write untouched")
        runner.expect(LocalVaultNoNetwork.requestCount, 0, "standalone session: cold restore and master-password unlock need no transport")

        let renewedStore = try reopenLocalVaultStore(in: directory)
        let renewed = makeLocalVaultHarness(store: renewedStore, keychain: keychain,
                                            tokenResults: [.success(Fixtures.tokenResponse()), .success(Fixtures.tokenResponse())])
        runner.expect(try await renewed.auth.restoreSession(), server.base.absoluteString, "standalone session: another repository discovers the same active local session")
        await renewed.api.setRefreshResponse(Fixtures.tokenResponse(accessToken: "standalone-fixture-bearer", refreshToken: rotatedRefresh))
        await runner.expectThrowsAsync("standalone session: restored locked session cannot refresh") { _ = try await renewed.auth.refresh() }
        runner.expectTrue(await renewed.api.refreshTokensUsed.isEmpty, "standalone session: lock makes no network request")
        try await renewed.auth.unlockWithMasterPassword(Fixtures.password)
        runner.expectTrue(try await renewed.auth.refresh(), "standalone session: refresh works after unlock and reconnect")
        runner.expectTrue(await renewed.api.refreshTokensUsed == [initialRefresh], "standalone session: refresh reads the token from SQL")
        runner.expect(await renewed.api.refreshServers, [server], "standalone session: refresh targets the restored deployment")
        runner.expectTrue(try await reopenedStore.localVaultSession()?.refreshToken == rotatedRefresh,
                          "standalone session: the rotated token is durable across SQLCipher handles")

        runner.expect(try await renewed.auth.login(email: Fixtures.email, password: Fixtures.password, server: equivalentServer), .success,
                      "standalone session: explicit sign-in works at an equivalent canonical base")
        runner.expect(await renewed.auth.session?.accountID, accountID, "standalone session: canonical sign-in reuses the same account ID")
        runner.expect(try await renewed.vault.cipher(id: savedID).notes, saved.notes, "standalone session: sign-in preserves confirmed cache data and ID")
        runner.expect(try await renewed.vault.cipher(id: draftID).notes, draft.notes, "standalone session: sign-in preserves the offline draft and ID")
        runner.expectTrue(try await renewedStore.outbox(accountID: accountID) == waiting,
                          "standalone session: sign-in neither replaces nor uploads the pending write")

        runner.expectTrue(await renewed.auth.logout(), "standalone session: sign-out confirms durable revocation")
        runner.expectTrue(try await renewedStore.localVaultSession() == nil, "standalone session: sign-out removes the active SQL row")
        let signedOutStore = try reopenLocalVaultStore(in: directory)
        let signedOut = makeLocalVaultHarness(store: signedOutStore, keychain: keychain)
        runner.expect(try await signedOut.auth.restoreSession(), nil, "standalone session: a cold launch after sign-out cannot revive the session")
        runner.expectTrue(try await signedOutStore.cipher(id: savedID, accountID: accountID) != nil,
                          "standalone session: sign-out does not delete the active account's cache")
        runner.expectTrue(try await signedOutStore.outbox(accountID: accountID) == waiting,
                          "standalone session: sign-out does not delete the active account's pending write")

        runner.expect(try await renewed.auth.login(email: Fixtures.email, password: Fixtures.password, server: otherServer), .success,
                      "standalone session: another deployment may sign in with the same email")
        runner.expect(await renewed.auth.session?.accountID, "https://vault.example.test/other|\(Fixtures.email)",
                      "standalone session: the reverse-proxy path still separates canonical account IDs")
        runner.expect(try await renewed.vault.ciphers().map(\.id), [], "standalone session: another deployment cannot read the prior cache")
        runner.expect(try await renewed.vault.outboxStatus().pendingCount, 0, "standalone session: another deployment cannot replay the prior queue")

        let signOutPeerStore = try reopenLocalVaultStore(in: directory)
        let signOutPeer = makeLocalVaultHarness(store: signOutPeerStore, keychain: keychain)
        runner.expect(try await signOutPeer.auth.restoreSession(), otherServer.base.absoluteString,
                      "standalone session: an independent reader restores the current deployment")
        await renewed.api.setRefreshResponse(Fixtures.tokenResponse(accessToken: "late-fixture-bearer", refreshToken: "late-fixture-refresh"))
        await renewed.api.pauseNextRefresh()
        let staleRefresh = Task { try await renewed.auth.refresh() }
        await renewed.api.waitUntilRefreshIsPaused()
        let peerSignedOut = await signOutPeer.auth.logout()
        await renewed.api.resumePausedRefresh()
        runner.expectTrue(peerSignedOut, "standalone session: an independent reader revokes the same durable session")
        await runner.expectThrowsAsync("standalone session: a late refresh cannot update the revoked SQL session") {
            _ = try await staleRefresh.value
        }
        runner.expectTrue(try await renewedStore.localVaultSession() == nil, "standalone session: late refresh does not republish a SQL row")
        let finalStore = try reopenLocalVaultStore(in: directory)
        let final = makeLocalVaultHarness(store: finalStore, keychain: keychain)
        runner.expect(try await final.auth.restoreSession(), nil, "standalone session: a cold launch cannot revive the late refresh")
    } catch {
        runner.expectTrue(false, "standalone session: unexpected fixture error \(error)")
    }

    runner.expectTrue(!spy.wasAccessed && spy.snapshot == existingMarkers,
                      "standalone session: no operation reads, writes or deletes legacy Keychain data")
}

func checkStandaloneRefreshRotationRace(_ runner: inout TestRunner) async {
    let seedToken = "local-rotation-fixture-initial"
    let winningToken = "local-rotation-fixture-winner"
    let staleToken = "local-rotation-fixture-stale"
    let spy = LocalVaultKeychainSpy(items: [:])
    let keychain = KeychainBridge(localMacService: "local-rotation-fixture", itemStore: spy)

    do {
        let (store, directory) = try await Fixtures.freshStore()
        defer { Fixtures.cleanup(directory) }
        let stale = makeLocalVaultHarness(store: store, keychain: keychain,
                                          tokenResults: [.success(Fixtures.tokenResponse(refreshToken: seedToken))])
        guard try await stale.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server) == .success,
              let sharedSession = try await store.localVaultSession(), sharedSession.refreshToken == seedToken else {
            runner.expectTrue(false, "standalone rotation: initial sign-in must publish the SQL session")
            return
        }
        let peerStore = try reopenLocalVaultStore(in: directory)
        let peer = makeLocalVaultHarness(store: peerStore, keychain: keychain)
        runner.expect(try await peer.auth.restoreSession(), Fixtures.server.base.absoluteString,
                      "standalone rotation: another process can restore the same durable session")
        runner.expect(try await peerStore.localVaultSession()?.id, sharedSession.id,
                      "standalone rotation: cold restore does not replace the durable session ID")
        try await peer.auth.unlockWithMasterPassword(Fixtures.password)

        await stale.api.setRefreshResponse(Fixtures.tokenResponse(accessToken: "local-rotation-stale-bearer", refreshToken: staleToken))
        await peer.api.setRefreshResponse(Fixtures.tokenResponse(accessToken: "local-rotation-winner-bearer", refreshToken: winningToken))
        await stale.api.pauseNextRefresh()
        let lateResponse = Task { try await stale.auth.refresh() }
        await stale.api.waitUntilRefreshIsPaused()
        let peerRefreshed = try? await peer.auth.refresh()
        await stale.api.resumePausedRefresh()

        runner.expect(peerRefreshed, true, "standalone rotation: the peer persists a new token first")
        await runner.expectThrowsAsync("standalone rotation: a late response using the prior token is rejected") {
            _ = try await lateResponse.value
        }
        let rotated = try await store.localVaultSession()
        runner.expect(rotated?.id, sharedSession.id, "standalone rotation: the winning write preserves the session ID")
        runner.expectTrue(rotated?.refreshToken == winningToken, "standalone rotation: a late result cannot overwrite the winning token")
        let tokens = await stale.api.accessTokensSet
        runner.expectTrue(tokens.last == .some(nil), "standalone rotation: the losing request leaves no bearer installed")

        runner.expectTrue(await peer.auth.logout(), "standalone rotation: the peer signs out")
        runner.expectTrue(await stale.auth.logout(), "standalone rotation: sign-out is successful if the former row is already absent")
        runner.expectTrue(!(await stale.auth.hasSession()), "standalone rotation: repeated revocation clears the old in-memory view")
        runner.expectTrue(try await store.localVaultSession() == nil, "standalone rotation: repeat sign-out cannot recreate a row")
    } catch {
        runner.expectTrue(false, "standalone rotation: unexpected fixture error \(error)")
    }

    runner.expectTrue(!spy.wasAccessed, "standalone rotation: both processes keep the Keychain untouched")
}

func checkStandaloneLockDuringRefresh(_ runner: inout TestRunner) async {
    let initialToken = "local-lock-fixture-initial"
    let rotatedToken = "local-lock-fixture-rotated"
    let cancelledRotation = "local-cancelled-fixture-rotated"
    let stagedBearer = "local-lock-fixture-staged-bearer"
    let spy = LocalVaultKeychainSpy(items: [:])
    let keychain = KeychainBridge(localMacService: "local-lock-fixture", itemStore: spy)

    do {
        let (store, directory) = try await Fixtures.freshStore()
        defer { Fixtures.cleanup(directory) }
        let live = makeLocalVaultHarness(store: store, keychain: keychain,
                                         tokenResults: [.success(Fixtures.tokenResponse(refreshToken: initialToken))])
        runner.expect(try await live.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server), .success,
                      "standalone refresh/lock: sign-in succeeds")
        let sessionID = try await store.localVaultSession()?.id
        await live.api.setRefreshResponse(Fixtures.tokenResponse(accessToken: stagedBearer, refreshToken: rotatedToken))
        await live.api.pauseNextRefresh()
        let refresh = Task { try await live.auth.refresh() }
        await live.api.waitUntilRefreshIsPaused()

        let completion = LocalVaultLockCompletion()
        let lock = Task {
            await live.auth.lock()
            await completion.markFinished()
        }
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !(await completion.finished), ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(20))
        }
        let lockedBeforeResponse = await completion.finished
        await live.api.resumePausedRefresh()
        await lock.value
        _ = await refresh.result

        runner.expectTrue(lockedBeforeResponse, "standalone refresh/lock: a paused remote grant cannot hold the vault unlocked")
        runner.expectTrue(!(await live.auth.isUnlocked()), "standalone refresh/lock: the late response cannot unlock the vault")
        let persisted = try await reopenLocalVaultStore(in: directory).localVaultSession()
        runner.expectTrue(sessionID != nil && persisted?.id == sessionID && persisted?.refreshToken == rotatedToken,
                          "standalone refresh/lock: the same durable session retains the token rotated by the server")
        let accessTokens = await live.api.accessTokensSet
        runner.expectTrue(!accessTokens.contains(stagedBearer), "standalone refresh/lock: no bearer from the stale unlocked incarnation is published")

        try await live.auth.unlockWithMasterPassword(Fixtures.password)
        let cancelledBearer = "local-cancelled-fixture-staged-bearer"
        await live.api.setRefreshResponse(Fixtures.tokenResponse(accessToken: cancelledBearer, refreshToken: cancelledRotation))
        await live.api.pauseNextRefresh()
        let cancelled = Task { try await live.auth.refresh() }
        await live.api.waitUntilRefreshIsPaused()
        cancelled.cancel()
        await live.api.resumePausedRefresh()
        await runner.expectThrowsAsync("standalone refresh cancellation: the cancelled caller cannot use the grant") {
            _ = try await cancelled.value
        }
        runner.expectTrue(try await store.localVaultSession()?.refreshToken == cancelledRotation,
                          "standalone refresh cancellation: a received rotation is preserved even when its caller cancels")
        let afterCancellation = await live.api.accessTokensSet
        runner.expectTrue(!afterCancellation.contains(cancelledBearer),
                          "standalone refresh cancellation: no bearer is published for the cancelled caller")
    } catch {
        runner.expectTrue(false, "standalone refresh/lock: unexpected fixture error \(error)")
    }

    runner.expectTrue(!spy.wasAccessed, "standalone refresh/lock: the Keychain remains untouched")
}

private actor LocalVaultLockCompletion {
    private(set) var finished = false

    func markFinished() { finished = true }
}

private func makeLocalVaultHarness(store: VaultStore, keychain: KeychainBridge, tokenResults: [TokenResult] = [])
    -> (api: FakeAPI, auth: AuthRepository, vault: VaultRepository, keyVault: KeyVault) {
    let api = FakeAPI(preloginResponse: Fixtures.prelogin(), tokenResults: tokenResults)
    let keyVault = KeyVault()
    let encryptor = UserKeyEncryptor()
    let auth = AuthRepository(api: api, keyVault: keyVault, keychain: keychain, store: store,
                              encryptor: encryptor, usesLocalSessionStore: true)
    let coordinator = VaultMutationCoordinator()
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: FakeIdentityStore(),
                            mutationCoordinator: coordinator)
    let vault = VaultRepository(api: api, store: store, keyVault: keyVault, encryptor: encryptor,
                                syncEngine: engine, mutationCoordinator: coordinator,
                                accountLease: { await auth.currentSessionLease() }, lockHandler: { await auth.lock() })
    return (api, auth, vault, keyVault)
}

private func reopenLocalVaultStore(in directory: URL) throws -> VaultStore {
    try VaultStore(databaseURL: directory.appendingPathComponent("vault.sqlite"), passphrase: Data("test-passphrase".utf8))
}

private func legacyLocalVaultMarkers(accountID: String) -> [String: Data] {
    [
        AppShared.KeychainAccount.activeAccountID: Data(accountID.utf8),
        AppShared.KeychainAccount.activeSessionID: Data(UUID().uuidString.utf8),
        AppShared.KeychainAccount.refreshToken(accountID: accountID): Data("legacy-fixture-refresh".utf8),
        AppShared.KeychainAccount.localAuthHash(accountID: accountID): Data("legacy-fixture-verifier".utf8),
        AppShared.KeychainAccount.rememberedDevice(accountID: accountID): Data("legacy-fixture-device".utf8),
    ]
}

private final class LocalVaultKeychainSpy: KeychainItemStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data]
    private var accessed = false

    init(items: [String: Data]) { self.items = items }

    var wasAccessed: Bool { lock.withLock { accessed } }
    var snapshot: [String: Data] { lock.withLock { items } }

    func set(_ data: Data, account: String, accessGroup: String, biometryGated: Bool) throws {
        lock.withLock { accessed = true }
        throw KeychainError.unavailable
    }

    func get(account: String, accessGroup: String) async throws -> Data? {
        lock.withLock {
            accessed = true
            return items[account]
        }
    }

    func delete(account: String, accessGroup: String) {
        lock.withLock {
            accessed = true
            items[account] = nil
        }
    }
}

private final class LocalVaultNoNetwork: URLProtocol, @unchecked Sendable {
    private final class Recorder: @unchecked Sendable {
        let lock = NSLock()
        var count = 0
    }

    private static let recorder = Recorder()
    static var requestCount: Int { recorder.lock.withLock { recorder.count } }

    static func reset() { recorder.lock.withLock { recorder.count = 0 } }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.recorder.lock.withLock { Self.recorder.count += 1 }
        client?.urlProtocol(self, didFailWithError: URLError(.notConnectedToInternet))
    }

    override func stopLoading() {}
}
#endif
