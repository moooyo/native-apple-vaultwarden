import Foundation
import VaultModels
import Networking
import SyncEngine
import VaultRepository
import Generators
import UIShared

// MARK: - Fake AuthService

/// In-memory `AuthService` for the unlock / login view models. Returns canned results or
/// throws canned errors, and records the calls made to it.
actor FakeAuthService: AuthService {
    // Canned login results, consumed FIFO (first = login, next = submitTwoFactor).
    var loginResults: [Result<LoginResult, Error>]
    var unlockMasterError: Error?
    var unlockBiometricsError: Error?
    var unlocked = false

    // Recording.
    private(set) var loginCalls: [(email: String, password: String, server: String)] = []
    private(set) var twoFactorCalls: [(provider: TwoFactorProvider, code: String, remember: Bool)] = []
    private(set) var unlockMasterCalls: [String] = []
    private(set) var biometricCalls: [String] = []
    private(set) var lockCount = 0

    init(loginResults: [Result<LoginResult, Error>] = []) {
        self.loginResults = loginResults
    }

    func setUnlockMasterError(_ e: Error?) { unlockMasterError = e }
    func setUnlockBiometricsError(_ e: Error?) { unlockBiometricsError = e }

    func login(email: String, password: String, serverURL: String) async throws -> LoginResult {
        loginCalls.append((email, password, serverURL))
        return try next()
    }

    func submitTwoFactor(provider: TwoFactorProvider, code: String,
                         remember: Bool, serverURL: String) async throws -> LoginResult {
        twoFactorCalls.append((provider, code, remember))
        return try next()
    }

    func unlockWithMasterPassword(_ password: String) async throws {
        unlockMasterCalls.append(password)
        if let unlockMasterError { throw unlockMasterError }
        unlocked = true
    }

    func unlockWithBiometrics(reason: String) async throws {
        biometricCalls.append(reason)
        if let unlockBiometricsError { throw unlockBiometricsError }
        unlocked = true
    }

    func isUnlocked() async -> Bool { unlocked }
    func lock() async { lockCount += 1; unlocked = false }

    private func next() throws -> LoginResult {
        guard !loginResults.isEmpty else { fatalError("FakeAuthService: no login result queued") }
        return try loginResults.removeFirst().get()
    }
}

// MARK: - Fake VaultService

/// In-memory `VaultService` for the vault-list / sync view models. Holds a list of ciphers,
/// supports a naive substring search over name/username, and returns a canned sync outcome.
actor FakeVaultService: VaultService {
    var stored: [PlaintextCipher]
    var ciphersError: Error?
    var searchError: Error?
    var syncError: Error?
    var syncOutcome: SyncOutcome

    private(set) var syncCallCount = 0
    private(set) var ciphersCallCount = 0
    private(set) var searchQueries: [String] = []
    private(set) var createdCiphers: [PlaintextCipher] = []
    private(set) var deletedIDs: [String] = []

    init(stored: [PlaintextCipher] = [],
         syncOutcome: SyncOutcome = SyncOutcome(upserted: 0, deletedLocally: 0, dropped: 0,
                                                droppedMessages: [], identitiesWritten: 0)) {
        self.stored = stored
        self.syncOutcome = syncOutcome
    }

    func setCiphersError(_ e: Error?) { ciphersError = e }
    func setSearchError(_ e: Error?) { searchError = e }
    func setSyncError(_ e: Error?) { syncError = e }
    func setStored(_ c: [PlaintextCipher]) { stored = c }

    func ciphers() async throws -> [PlaintextCipher] {
        ciphersCallCount += 1
        if let ciphersError { throw ciphersError }
        return stored
    }

    func cipher(id: String) async throws -> PlaintextCipher {
        guard let c = stored.first(where: { $0.id == id }) else { throw RepositoryError.cipherNotFound }
        return c
    }

    func search(_ query: String) async throws -> [PlaintextCipher] {
        searchQueries.append(query)
        if let searchError { throw searchError }
        let q = query.lowercased()
        return stored.filter { c in
            c.name.lowercased().contains(q) || (c.login?.username?.lowercased().contains(q) ?? false)
        }
    }

    func createCipher(_ cipher: PlaintextCipher) async throws -> String {
        createdCiphers.append(cipher)
        let id = cipher.id ?? "new-\(createdCiphers.count)"
        return id
    }

    func updateCipher(id: String, _ cipher: PlaintextCipher) async throws {
        if let idx = stored.firstIndex(where: { $0.id == id }) { stored[idx] = cipher }
    }

    func deleteCipher(id: String) async throws {
        deletedIDs.append(id)
        stored.removeAll { $0.id == id }
    }

    func sync() async throws -> SyncOutcome {
        syncCallCount += 1
        if let syncError { throw syncError }
        return syncOutcome
    }
}

// MARK: - Deterministic random source

/// A `RandomSource` that returns a fixed, repeating sequence so generator output is
/// deterministic in tests.
struct MockRandomSource: RandomSource {
    let sequence: [Int]
    init(_ sequence: [Int]) { self.sequence = sequence }

    // A class would let us mutate an index, but RandomSource is `Sendable` value-typed; use a
    // reference box for the cursor.
    final class Cursor: @unchecked Sendable { var i = 0 }
    private let cursor = Cursor()

    func int(upperBound: Int) -> Int {
        guard upperBound > 0 else { return 0 }
        let value = sequence.isEmpty ? 0 : sequence[cursor.i % sequence.count]
        cursor.i += 1
        return value % upperBound
    }
}
