#if os(macOS)
import AppShared
import CryptoCore
import Foundation
import KeychainBridge
import KeyVault
import Networking
import SyncEngine
import UIShared
import VaultRepository
import VaultStore

func checkMacSessionTimeoutCAS(_ runner: inout TestRunner) async {
    do {
        let (store, directory) = try await Fixtures.freshStore()
        defer { Fixtures.cleanup(directory) }
        let keychain = KeychainBridge.withoutSystemStorage()
        let first = timeoutHarness(store: store, keychain: keychain, usesLocalSessionStore: true, attempts: 2)
        let beforePublishing = ContinuousClock.now
        try await signInForTimeout(first.auth)
        guard let firstLease = await first.auth.currentSessionLease() else {
            runner.expectTrue(false, "Mac timeout CAS: seed lease is published")
            return
        }
        let signalTime = ContinuousClock.now
        runner.expect(await first.auth.sessionTimeoutLease(publishedBy: beforePublishing), nil,
                      "Mac timeout CAS: a delayed signal misses a session that did not yet exist")
        runner.expect(await first.auth.sessionTimeoutLease(publishedBy: signalTime), firstLease,
                      "Mac timeout CAS: a signal captures the exact published session")

        await first.auth.lock()
        let beforeUnlock = ContinuousClock.now
        try await first.auth.unlockWithMasterPassword(Fixtures.password)
        runner.expect(await first.auth.expireSession(firstLease, logOut: false, systemEventAt: beforeUnlock), .locked,
                      "Mac timeout CAS: a system event still locks a session whose lock lease rotated before an unlock completed")
        runner.expectTrue(!(await first.keyVault.isUnlocked), "Mac timeout CAS: the old session key is dropped")

        try await signInForTimeout(first.auth)
        runner.expect(await first.auth.expireSession(firstLease, logOut: true, systemEventAt: signalTime), .superseded,
                      "Mac timeout CAS: a queued logout cannot remove a newer login of the same account")
        runner.expect(await first.auth.expireSession(firstLease, logOut: false), .superseded,
                      "Mac timeout CAS: an old numeric deadline cannot lock a newer login")
        runner.expectTrue(await first.keyVault.isUnlocked, "Mac timeout CAS: stale work leaves the newer keys usable")

        let reopened = timeoutHarness(store: store, keychain: keychain, usesLocalSessionStore: true)
        runner.expect(try await reopened.auth.restoreSession(), Fixtures.server.base.absoluteString,
                      "Mac timeout restart: restore finds the previously installed session")
        runner.expectTrue(!(await reopened.keyVault.isUnlocked), "Mac timeout restart: restore never recovers an unlocked vault key")
        guard let lockedLease = await reopened.auth.currentSessionLease() else {
            runner.expectTrue(false, "Mac timeout restart: the cold session has a locked lease")
            return
        }
        runner.expect(await reopened.auth.expireSession(lockedLease, logOut: true), .loggedOut,
                      "Mac timeout restart: logout can durably remove the already locked session")
        runner.expect(try await store.localVaultSession(), nil, "Mac timeout restart: the SQL session marker is gone")
        let afterLogout = timeoutHarness(store: store, keychain: keychain, usesLocalSessionStore: true)
        runner.expect(try await afterLogout.auth.restoreSession(), nil,
                      "Mac timeout restart: the logout survives a new repository process")
    } catch {
        runner.expectTrue(false, "Mac timeout CAS: unexpected error \(error)")
    }
}

func checkMacSessionTimeoutRevocationFailures(_ runner: inout TestRunner) async {
    do {
        let (store, directory) = try await Fixtures.freshStore()
        defer { Fixtures.cleanup(directory) }
        let itemStore = TimeoutKeychainStore()
        let keychain = KeychainBridge(localMacService: "timeout-test", itemStore: itemStore)
        let harness = timeoutHarness(store: store, keychain: keychain, usesLocalSessionStore: false, attempts: 1)
        try await signInForTimeout(harness.auth)
        guard let lease = await harness.auth.currentSessionLease() else {
            runner.expectTrue(false, "Mac timeout revocation: seed lease is published")
            return
        }
        await harness.api.setRefreshResponse(Fixtures.tokenResponse(accessToken: "timeout-late-refresh"))
        await harness.api.pauseNextRefresh()
        let refresh = Task { try await harness.auth.refresh() }
        await harness.api.waitUntilRefreshIsPaused()
        let locked = await harness.auth.expireSession(lease, logOut: false)
        await harness.api.resumePausedRefresh()
        _ = try? await refresh.value
        runner.expect(locked, .locked, "Mac timeout revocation: session lock does not wait on a stalled network refresh")
        runner.expectTrue(!(await harness.keyVault.isUnlocked), "Mac timeout revocation: late refresh does not restore in-memory keys")
        guard let newLease = await harness.auth.currentSessionLease() else {
            runner.expectTrue(false, "Mac timeout revocation: lock preserves the account session")
            return
        }
        itemStore.rejectActiveAccountDeletion(true)
        runner.expect(await harness.auth.expireSession(newLease, logOut: true), .logoutFailedLocked,
                      "Mac timeout revocation: failure to remove a durable shared marker is not reported as logout")
        runner.expectTrue(itemStore.hasActiveAccount, "Mac timeout revocation: failed shared deletion is observable")
        runner.expectTrue(!(await harness.keyVault.isUnlocked), "Mac timeout revocation: shared marker failure retains a locked vault")
        let adapter = AuthServiceAdapter(repository: harness.auth)
        runner.expectTrue(!(await adapter.logout()), "Mac timeout revocation: manual retry cannot report success while the shared marker remains")
        itemStore.rejectActiveAccountDeletion(false)
        runner.expectTrue(await adapter.logout(),
                      "Mac timeout revocation: retry confirms removal of the durable shared marker")
        runner.expectTrue(!itemStore.hasActiveAccount, "Mac timeout revocation: success removes the shared active account")

        let noKeychain = KeychainBridge.withoutSystemStorage()
        let original = timeoutHarness(store: store, keychain: noKeychain, usesLocalSessionStore: true, attempts: 1)
        let replacement = timeoutHarness(store: store, keychain: noKeychain, usesLocalSessionStore: true, attempts: 1)
        try await signInForTimeout(original.auth)
        guard let originalLease = await original.auth.currentSessionLease() else {
            runner.expectTrue(false, "Mac timeout revocation: standalone seed lease is published")
            return
        }
        try await signInForTimeout(replacement.auth)
        let active = try await store.localVaultSession()
        runner.expect(await original.auth.expireSession(originalLease, logOut: true), .logoutFailedLocked,
                      "Mac timeout revocation: a lost SQL session compare-and-delete safely falls back to lock")
        runner.expectTrue(!(await original.keyVault.isUnlocked), "Mac timeout revocation: CAS loss drops the old in-memory keys")
        runner.expect(try await store.localVaultSession(), active,
                      "Mac timeout revocation: CAS loss does not delete a separate process's replacement session")
    } catch {
        runner.expectTrue(false, "Mac timeout revocation: unexpected error \(error)")
    }
}

func checkMacSessionTimeoutWhileLocking(_ runner: inout TestRunner) async {
    do {
        let (store, directory) = try await Fixtures.freshStore()
        defer { Fixtures.cleanup(directory) }
        let keychain = KeychainBridge.withoutSystemStorage()
        let encryptor = TimeoutEncryptor()
        let harness = timeoutHarness(store: store, keychain: keychain, usesLocalSessionStore: true, attempts: 1, encryptor: encryptor)
        try await signInForTimeout(harness.auth)
        guard let lease = await harness.auth.currentSessionLease() else {
            runner.expectTrue(false, "Mac timeout during lock: seed lease is published")
            return
        }

        await encryptor.pauseNextClear()
        let lock = Task { await harness.auth.lock() }
        await encryptor.waitUntilPaused()
        let signalTime = ContinuousClock.now
        runner.expect(await harness.auth.currentSessionLease(), nil, "Mac timeout during lock: ordinary work cannot acquire a lease while clearing keys")
        let lookup = Task { await harness.auth.sessionTimeoutLease(publishedBy: signalTime) }
        let expiration = Task { await harness.auth.expireSession(lease, logOut: true, systemEventAt: signalTime) }
        await encryptor.resumeClear()
        await lock.value
        let logout = await expiration.value
        _ = await lookup.value
        runner.expect(logout, .loggedOut, "Mac timeout during lock: sleep-time logout survives an in-flight manual lock")
        runner.expect(try await store.localVaultSession(), nil, "Mac timeout during lock: the durable record does not return")
    } catch {
        runner.expectTrue(false, "Mac timeout during lock: unexpected error \(error)")
    }
}

private func timeoutHarness(store: VaultStore, keychain: KeychainBridge, usesLocalSessionStore: Bool, attempts: Int = 0,
                            encryptor: any VaultEncrypting = UserKeyEncryptor())
    -> (auth: AuthRepository, keyVault: KeyVault, api: FakeAPI) {
    let api = FakeAPI(preloginResponse: Fixtures.prelogin(), tokenResults: Array(repeating: .success(Fixtures.tokenResponse()), count: attempts))
    let keys = KeyVault()
    let auth = AuthRepository(api: api, keyVault: keys, keychain: keychain, store: store,
                              encryptor: encryptor, usesLocalSessionStore: usesLocalSessionStore)
    return (auth, keys, api)
}

private func signInForTimeout(_ auth: AuthRepository) async throws {
    let result = try await auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
    guard result == .success else { throw RepositoryError.authenticationFailed }
}

private final class TimeoutKeychainStore: KeychainItemStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]
    private var rejectAccountDeletion = false

    var hasActiveAccount: Bool { lock.withLock { items[AppShared.KeychainAccount.activeAccountID] != nil } }
    func rejectActiveAccountDeletion(_ value: Bool) { lock.withLock { rejectAccountDeletion = value } }

    func set(_ data: Data, account: String, accessGroup: String, biometryGated: Bool) throws {
        lock.withLock { items[account] = data }
    }

    func get(account: String, accessGroup: String) async throws -> Data? {
        lock.withLock { items[account] }
    }

    func delete(account: String, accessGroup: String) {
        lock.withLock {
            if account != AppShared.KeychainAccount.activeAccountID || !rejectAccountDeletion { items[account] = nil }
        }
    }
}

private actor TimeoutEncryptor: VaultEncrypting {
    private let encryptor = UserKeyEncryptor()
    private var shouldPause = false
    private var gate: CheckedContinuation<Void, Never>?
    private var observer: CheckedContinuation<Void, Never>?

    func encrypt(_ plaintext: Data, cipherKey: SymmetricCryptoKey?) async throws -> EncString {
        try await encryptor.encrypt(plaintext, cipherKey: cipherKey)
    }

    func setUserKey(_ key: SymmetricCryptoKey) async { await encryptor.setUserKey(key) }
    func hasKey() async -> Bool { await encryptor.hasKey() }

    func clear() async {
        if shouldPause {
            shouldPause = false
            await withCheckedContinuation { continuation in
                gate = continuation
                observer?.resume()
                observer = nil
            }
        }
        await encryptor.clear()
    }

    func pauseNextClear() { shouldPause = true }
    func waitUntilPaused() async {
        if gate != nil { return }
        await withCheckedContinuation { observer = $0 }
    }
    func resumeClear() {
        gate?.resume()
        gate = nil
    }
}
#endif
