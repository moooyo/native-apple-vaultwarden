#if os(macOS)
import CryptoCore
import Foundation
import KeychainBridge
import KeyVault
import Networking
import Synchronization
import VaultRepository
import VaultStore

func checkLocalBiometricUnlock(_ runner: inout TestRunner) async {
    do {
        let (store, directory) = try await Fixtures.freshStore()
        defer { Fixtures.cleanup(directory) }
        let wrapper = LocalBiometricWrapperFixture()
        let initial = LocalBiometricRepositoryFixture(store: store, wrapper: wrapper, allowLogin: true)
        runner.expect(try await initial.signIn(), .success, "standalone Touch ID: sign-in succeeds without enrollment")
        guard let activeSession = try await store.localVaultSession() else {
            runner.expectTrue(false, "standalone Touch ID: sign-in publishes a durable session")
            return
        }
        runner.expect(await initial.auth.localBiometricUnlockEnabled(), false, "standalone Touch ID: starts disabled")
        runner.expect(wrapper.wrapBindings.count, 0, "standalone Touch ID: sign-in does not wrap the user key")
        await initial.auth.lock()
        await runner.expectThrowsAsync("standalone Touch ID: a locked vault cannot enroll") {
            try await initial.auth.setBiometricUnlockEnabled(true)
        }
        runner.expect(wrapper.wrapBindings.count, 0, "standalone Touch ID: locked enrollment never calls the wrapper")

        try await initial.unlockWithPassword()
        wrapper.setWrapError(.unavailable)
        await runner.expectThrowsAsync("standalone Touch ID: a failed enrollment is reported") {
            try await initial.auth.setBiometricUnlockEnabled(true)
        }
        runner.expect(await initial.auth.localBiometricUnlockEnabled(), false, "standalone Touch ID: failed enrollment stays disabled")
        runner.expect(try await store.localBiometricEnvelope(accountID: activeSession.accountID, sessionID: activeSession.id), nil,
                      "standalone Touch ID: failed enrollment does not persist an envelope")
        runner.expect(await initial.auth.isUnlocked(), true, "standalone Touch ID: failed enrollment does not lock the current vault")
        wrapper.setWrapError(nil)
        try await initial.auth.setBiometricUnlockEnabled(true)
        runner.expect(await initial.auth.localBiometricUnlockEnabled(), true, "standalone Touch ID: unlocked enrollment succeeds")

        await initial.auth.lock()
        await initial.checkLocked(&runner, context: "normal lock")
        runner.expect(await initial.auth.localBiometricUnlockEnabled(), true, "standalone Touch ID: lock preserves enrollment")
        try await initial.auth.unlockWithBiometrics(reason: "Unlock before restart")
        try await initial.checkUsableKeys(&runner, context: "warm unlock")
        await initial.auth.lock()

        let coldStore = try reopenBiometricFixtureStore(in: directory)
        let cold = LocalBiometricRepositoryFixture(store: coldStore, wrapper: wrapper)
        runner.expect(try await cold.auth.restoreSession(), Fixtures.server.base.absoluteString, "standalone Touch ID: cold restore finds the same session")
        await cold.checkLocked(&runner, context: "cold restore")
        runner.expect(await cold.auth.localBiometricUnlockEnabled(), true, "standalone Touch ID: enrollment survives a new database handle")
        try await cold.auth.unlockWithBiometrics(reason: "Unlock after restart")
        try await cold.checkUsableKeys(&runner, context: "cold unlock")
        let requests = wrapper.unwrapRequests
        runner.expect(requests.map(\.reason), ["Unlock before restart", "Unlock after restart"], "standalone Touch ID: reasons reach the wrapper")
        runner.expectTrue(requests.count == 2 && requests.first?.envelope == requests.last?.envelope
                          && requests.first?.binding == requests.last?.binding,
                          "standalone Touch ID: cold unlock uses the same opaque envelope and binding")
        runner.expect(try await coldStore.localBiometricEnvelope(accountID: activeSession.accountID, sessionID: activeSession.id), requests.first?.envelope,
                      "standalone Touch ID: the request uses the envelope stored for the exact session")

        for failure: KeychainError in [.unavailable, .userCanceled] {
            await cold.auth.lock()
            wrapper.setUnwrapError(failure)
            let requestCount = wrapper.unwrapRequests.count
            await runner.expectThrowsAsync("standalone Touch ID: \(failure) cannot unlock") {
                try await cold.auth.unlockWithBiometrics(reason: "Failed unlock")
            }
            runner.expect(wrapper.unwrapRequests.count, requestCount + 1, "standalone Touch ID: unlock exercises \(failure) from the wrapper")
            await cold.checkLocked(&runner, context: "failed unwrap (\(failure))")
            try await cold.unlockWithPassword()
            try await cold.checkUsableKeys(&runner, context: "master password after \(failure)")
            try await cold.auth.setBiometricUnlockEnabled(true)
        }
    } catch {
        runner.expectTrue(false, "standalone Touch ID: unexpected fixture error \(error)")
    }
}

func checkLocalBiometricRevocation(_ runner: inout TestRunner) async {
    do {
        let (store, directory) = try await Fixtures.freshStore()
        defer { Fixtures.cleanup(directory) }
        let wrapper = LocalBiometricWrapperFixture()
        let original = LocalBiometricRepositoryFixture(store: store, wrapper: wrapper, allowLogin: true)
        runner.expect(try await original.signIn(), .success, "standalone Touch ID revocation: original sign-in succeeds")
        guard let firstSession = try await store.localVaultSession() else {
            runner.expectTrue(false, "standalone Touch ID revocation: sign-in publishes a durable session")
            return
        }
        try await original.auth.setBiometricUnlockEnabled(true)
        try await original.auth.setBiometricUnlockEnabled(false)
        await original.auth.lock()
        await original.checkUnavailable(&runner, wrapper: wrapper, context: "disabling Touch ID")
        runner.expect(try await store.localBiometricEnvelope(accountID: firstSession.accountID, sessionID: firstSession.id), nil,
                      "standalone Touch ID revocation: disabling durably removes the envelope")
        try await original.unlockWithPassword()
        try await original.auth.setBiometricUnlockEnabled(true)
        let firstBinding = wrapper.wrapBindings.last
        await original.auth.lock()

        let peerStore = try reopenBiometricFixtureStore(in: directory)
        let replacement = LocalBiometricRepositoryFixture(store: peerStore, wrapper: wrapper, allowLogin: true)
        runner.expect(try await replacement.signIn(), .success, "standalone Touch ID revocation: same-account replacement succeeds")
        let replacementSession = try await peerStore.localVaultSession()
        runner.expectTrue(firstSession.accountID == replacementSession?.accountID && firstSession.id != replacementSession?.id,
                          "standalone Touch ID revocation: same account gets a new session UUID")
        await original.checkUnavailable(&runner, wrapper: wrapper, context: "replacing the durable session")
        await replacement.auth.lock()
        await replacement.checkUnavailable(&runner, wrapper: wrapper, context: "new same-account session")
        try await replacement.unlockWithPassword()
        try await replacement.auth.setBiometricUnlockEnabled(true)
        runner.expectTrue(firstBinding != nil && wrapper.wrapBindings.last != firstBinding,
                          "standalone Touch ID revocation: same-account enrollment binds a different session UUID")

        runner.expect(await replacement.auth.logout(), true, "standalone Touch ID revocation: sign-out succeeds")
        runner.expect(try await peerStore.localVaultSession(), nil, "standalone Touch ID revocation: sign-out removes the session")
        let cold = LocalBiometricRepositoryFixture(store: try reopenBiometricFixtureStore(in: directory), wrapper: wrapper)
        runner.expect(try await cold.auth.restoreSession(), nil, "standalone Touch ID revocation: no cold session survives sign-out")
        await cold.checkUnavailable(&runner, wrapper: wrapper, context: "cold start after sign-out")
    } catch {
        runner.expectTrue(false, "standalone Touch ID revocation: unexpected fixture error \(error)")
    }
}

func checkLocalBiometricInterruption(_ runner: inout TestRunner) async {
    for action in LocalBiometricInterruption.allCases {
        do {
            let (store, directory) = try await Fixtures.freshStore()
            defer { Fixtures.cleanup(directory) }
            let wrapper = LocalBiometricWrapperFixture()
            let fixture = LocalBiometricRepositoryFixture(store: store, wrapper: wrapper, allowLogin: true)
            runner.expect(try await fixture.signIn(), .success, "standalone Touch ID \(action): initial sign-in succeeds")
            try await fixture.auth.setBiometricUnlockEnabled(true)
            await fixture.auth.lock()
            guard let originalSession = try await store.localVaultSession() else {
                runner.expectTrue(false, "standalone Touch ID \(action): sign-in publishes a durable session")
                continue
            }
            let actingAuth: AuthRepository
            if action.isPeerAction {
                let peerStore = try reopenBiometricFixtureStore(in: directory)
                let peer = LocalBiometricRepositoryFixture(store: peerStore, wrapper: wrapper)
                runner.expect(try await peer.auth.restoreSession(), Fixtures.server.base.absoluteString,
                              "standalone Touch ID \(action): another database handle restores the same session")
                actingAuth = peer.auth
            } else {
                actingAuth = fixture.auth
            }

            await wrapper.prompt.pauseNext()
            let pendingUnlock = Task { try await fixture.auth.unlockWithBiometrics(reason: "Suspend test prompt") }
            guard await waitForBiometricFixture({ await wrapper.prompt.isSuspended }) else {
                runner.expectTrue(false, "standalone Touch ID \(action): the wrapper receives a suspended prompt")
                pendingUnlock.cancel()
                await wrapper.prompt.release()
                _ = try? await pendingUnlock.value
                continue
            }
            let completion = LocalBiometricPromptCompletion()
            let interruption = Task {
                let result: Result<Bool, Error>
                do { result = .success(try await action.apply(to: actingAuth)) }
                catch { result = .failure(error) }
                await completion.finish()
                return result
            }
            let finishedWhileSuspended = await waitForBiometricFixture { await completion.finished }
            runner.expectTrue(finishedWhileSuspended, "standalone Touch ID \(action): does not wait for an in-flight prompt")
            await wrapper.prompt.release()
            runner.expect(try await interruption.value.get(), true, "standalone Touch ID \(action): revocation operation succeeds")
            await runner.expectThrowsAsync("standalone Touch ID \(action): a late successful unwrap is discarded") {
                try await pendingUnlock.value
            }
            await fixture.checkLocked(&runner, context: "late successful unwrap after \(action)")
            runner.expect(await fixture.auth.localBiometricUnlockEnabled(), action == .lock || action == .peerReenroll,
                          "standalone Touch ID \(action): the durable enrollment reflects the completed operation")
            if action == .peerReenroll {
                let reenrolled = try await store.localBiometricEnvelope(accountID: originalSession.accountID, sessionID: originalSession.id)
                runner.expectTrue(reenrolled != nil && reenrolled != wrapper.unwrapRequests.first?.envelope,
                                  "standalone Touch ID: peer re-enrollment changes the envelope without replacing the session UUID")
                try await fixture.auth.unlockWithBiometrics(reason: "Unlock with replacement enrollment")
                try await fixture.checkUsableKeys(&runner, context: "fresh unwrap after peer re-enrollment")
            }
        } catch {
            runner.expectTrue(false, "standalone Touch ID \(action): unexpected fixture error \(error)")
        }
    }
}

private struct LocalBiometricRepositoryFixture {
    let auth: AuthRepository
    let keyVault = KeyVault()
    let encryptor = UserKeyEncryptor()

    init(store: VaultStore, wrapper: LocalBiometricWrapperFixture, allowLogin: Bool = false) {
        let tokenResults: [TokenResult] = allowLogin ? [.success(Fixtures.tokenResponse())] : []
        let api = FakeAPI(preloginResponse: Fixtures.prelogin(), tokenResults: tokenResults)
        auth = AuthRepository(api: api, keyVault: keyVault, keychain: .withoutSystemStorage(), store: store,
                              encryptor: encryptor, usesLocalSessionStore: true, localBiometrics: wrapper)
    }

    func signIn() async throws -> LoginResult {
        try await auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
    }

    func unlockWithPassword() async throws {
        try await auth.unlockWithMasterPassword(Fixtures.password)
    }

    func checkUnavailable(_ runner: inout TestRunner, wrapper: LocalBiometricWrapperFixture, context: String) async {
        let requestCount = wrapper.unwrapRequests.count
        runner.expect(await auth.localBiometricUnlockEnabled(), false, "standalone Touch ID after \(context): enrollment is unavailable")
        await runner.expectThrowsAsync("standalone Touch ID after \(context): cannot unlock") {
            try await auth.unlockWithBiometrics(reason: "Unavailable unlock")
        }
        runner.expect(wrapper.unwrapRequests.count, requestCount, "standalone Touch ID after \(context): does not even prompt")
        await checkLocked(&runner, context: context)
    }

    func checkLocked(_ runner: inout TestRunner, context: String) async {
        runner.expect(await keyVault.isUnlocked, false, "standalone Touch ID after \(context): no read key")
        runner.expect(await encryptor.hasKey(), false, "standalone Touch ID after \(context): no write key")
    }

    func checkUsableKeys(_ runner: inout TestRunner, context: String) async throws {
        let text = "Persisted vault example"
        let existingCipher = try EncString(parsing: Fixtures.enc(text))
        runner.expect(try await keyVault.decryptString(existingCipher), text, "standalone Touch ID after \(context): can decrypt existing data")
        let newCipher = try await encryptor.encryptString(text)
        runner.expect(try await keyVault.decryptString(newCipher), text, "standalone Touch ID after \(context): can encrypt new data")
    }
}

private func reopenBiometricFixtureStore(in directory: URL) throws -> VaultStore {
    try VaultStore(databaseURL: directory.appendingPathComponent("vault.sqlite"), passphrase: Data("test-passphrase".utf8))
}

private final class LocalBiometricWrapperFixture: LocalBiometricKeyWrapping {
    struct UnwrapRequest {
        let envelope: Data
        let binding: Data
        let reason: String
    }

    private struct State {
        var records: [Data: (binding: Data, key: SymmetricCryptoKey)] = [:]
        var wrapBindings: [Data] = []
        var unwrapRequests: [UnwrapRequest] = []
        var wrapError: KeychainError?
        var unwrapError: KeychainError?
    }

    private let state = Mutex(State())
    let prompt = LocalBiometricPrompt()

    var wrapBindings: [Data] { state.withLock { $0.wrapBindings } }
    var unwrapRequests: [UnwrapRequest] { state.withLock { $0.unwrapRequests } }

    func setWrapError(_ error: KeychainError?) { state.withLock { $0.wrapError = error } }
    func setUnwrapError(_ error: KeychainError?) { state.withLock { $0.unwrapError = error } }

    func wrap(_ userKey: SymmetricCryptoKey, binding: Data) throws -> Data {
        try state.withLock { state in
            state.wrapBindings.append(binding)
            if let error = state.wrapError { throw error }
            let envelope = Data(UUID().uuidString.utf8)
            state.records[envelope] = (binding, userKey)
            return envelope
        }
    }

    func unwrap(_ envelope: Data, binding: Data, reason: String) async throws -> SymmetricCryptoKey {
        let key = try state.withLock { state in
            state.unwrapRequests.append(UnwrapRequest(envelope: envelope, binding: binding, reason: reason))
            if let error = state.unwrapError { throw error }
            guard let record = state.records[envelope], record.binding == binding else { throw KeychainError.notFound }
            return record.key
        }
        await prompt.suspendIfRequested()
        return key
    }
}

private actor LocalBiometricPrompt {
    private var shouldPause = false
    private var pending: CheckedContinuation<Void, Never>?
    var isSuspended: Bool { pending != nil }

    func pauseNext() { shouldPause = true }

    func suspendIfRequested() async {
        guard shouldPause else { return }
        shouldPause = false
        await withCheckedContinuation { pending = $0 }
    }

    func release() {
        shouldPause = false
        pending?.resume()
        pending = nil
    }
}

private enum LocalBiometricInterruption: String, CaseIterable {
    case lock, disable, logout, peerDisable, peerReenroll

    var isPeerAction: Bool { self == .peerDisable || self == .peerReenroll }

    func apply(to auth: AuthRepository) async throws -> Bool {
        switch self {
        case .lock: await auth.lock()
        case .disable, .peerDisable: try await auth.setBiometricUnlockEnabled(false)
        case .logout: return await auth.logout()
        case .peerReenroll:
            try await auth.unlockWithMasterPassword(Fixtures.password)
            try await auth.setBiometricUnlockEnabled(false)
            try await auth.setBiometricUnlockEnabled(true)
        }
        return true
    }
}

private actor LocalBiometricPromptCompletion {
    private(set) var finished = false

    func finish() { finished = true }
}

private func waitForBiometricFixture(_ condition: () async -> Bool) async -> Bool {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while ContinuousClock.now < deadline {
        if await condition() { return true }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return false
}
#endif
