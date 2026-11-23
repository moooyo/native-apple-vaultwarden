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
    var logoutSucceeds = true
    var unlocked = false
    var sessionAvailable = false
    private var email: String?
    private let kdfIterations: Int?

    // Recording.
    private(set) var loginCalls: [(email: String, password: String, server: String)] = []
    private(set) var twoFactorCalls: [(provider: TwoFactorProvider, code: String, remember: Bool)] = []
    private(set) var unlockMasterCalls: [String] = []
    private(set) var biometricCalls: [String] = []
    private(set) var biometricSettings: [Bool] = []
    private(set) var emailCodeRequests: [String] = []
    private(set) var hintRequests: [String] = []
    private(set) var cancelledChallenges: [String] = []
    private(set) var lockCount = 0
    private(set) var logoutCount = 0

    init(loginResults: [Result<LoginResult, Error>] = [], email: String? = nil, unlocked: Bool = false,
         kdfIterations: Int? = nil) {
        self.loginResults = loginResults
        self.email = email
        self.kdfIterations = kdfIterations
        self.sessionAvailable = email != nil
        self.unlocked = unlocked
    }

    func setUnlockMasterError(_ e: Error?) { unlockMasterError = e }
    func setUnlockBiometricsError(_ e: Error?) { unlockBiometricsError = e }
    func setLogoutSucceeds(_ succeeds: Bool) { logoutSucceeds = succeeds }

    func login(email: String, password: String, serverURL: String) async throws -> LoginResult {
        loginCalls.append((email, password, serverURL))
        return try next(email: email)
    }

    func submitTwoFactor(provider: TwoFactorProvider, code: String,
                         remember: Bool, serverURL: String) async throws -> LoginResult {
        twoFactorCalls.append((provider, code, remember))
        return try next(email: loginCalls.last?.email)
    }

    func sendTwoFactorEmail(serverURL: String) async throws {
        emailCodeRequests.append(serverURL)
    }

    func requestPasswordHint(email: String, serverURL: String) async throws { hintRequests.append(email) }
    func cancelTwoFactor(email: String, serverURL: String) async { cancelledChallenges.append(email) }
    func accountEmail() async -> String? { email }
    func accountKDFIterations() async -> Int? { sessionAvailable ? kdfIterations : nil }

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
    func transferSession() async -> AccountSessionLease? {
        unlocked ? AccountSessionLease(accountID: "test", generation: UInt64(lockCount + logoutCount)) : nil
    }
    func verifyTransferPassword(_ password: String, for lease: AccountSessionLease) async throws {
        guard await transferSession() == lease, password == "test-password" else {
            throw RepositoryError.authenticationFailed
        }
    }
    func setBiometricUnlockEnabled(_ enabled: Bool) async throws {
        biometricSettings.append(enabled)
    }
    func hasSession() async -> Bool { sessionAvailable }
    func lock() async { lockCount += 1; unlocked = false }
    func logout() async -> Bool {
        logoutCount += 1
        guard logoutSucceeds else { return false }
        sessionAvailable = false
        unlocked = false
        email = nil
        return true
    }

    private func next(email: String?) throws -> LoginResult {
        guard !loginResults.isEmpty else { fatalError("FakeAuthService: no login result queued") }
        let result = try loginResults.removeFirst().get()
        if result == .success {
            self.email = email
            sessionAvailable = true
            unlocked = true
        }
        return result
    }
}

// MARK: - Fake VaultService

/// In-memory `VaultService` for the vault-list / sync view models. Holds a list of ciphers,
/// supports a naive substring search over name/username, and returns a canned sync outcome.
actor FakeVaultService: VaultService {
    private var recentIDs: [String] = []
    private var recentItemsError: Error?

    func recentItemIDs(limit: Int) async throws -> [String] {
        if let recentItemsError { throw recentItemsError }
        let active = Set(stored.filter { $0.deletedDate == nil && $0.archivedDate == nil }.compactMap(\.id))
        return Array(recentIDs.filter(active.contains).prefix(max(0, limit)))
    }

    func recordUse(id: String) async {
        recentIDs.removeAll { $0 == id }
        recentIDs.insert(id, at: 0)
    }

    var stored: [PlaintextCipher]
    var storedFolders: [PlaintextFolder]
    nonisolated let sendService: (any VaultSendService)?
    var ciphersError: Error?
    var searchError: Error?
    var syncError: Error?
    var syncOutcome: SyncOutcome
    private var outboxSnapshot = VaultOutboxStatus()
    private var outboxReadError: Error?
    private var listingHook: (@Sendable () async -> Void)?
    private var outboxReadHook: (@Sendable () async -> Void)?

    private(set) var syncCallCount = 0
    private(set) var outboxRequests: [AccountSessionLease?] = []
    private(set) var ciphersCallCount = 0
    private(set) var searchQueries: [String] = []
    private(set) var createdCiphers: [PlaintextCipher] = []
    private(set) var deletedIDs: [String] = []

    init(stored: [PlaintextCipher] = [], folders: [PlaintextFolder] = [],
         sendService: (any VaultSendService)? = nil,
         syncOutcome: SyncOutcome = SyncOutcome(upserted: 0, deletedLocally: 0, dropped: 0,
                                                droppedMessages: [], identitiesWritten: 0)) {
        self.stored = stored
        self.storedFolders = folders
        self.sendService = sendService
        self.syncOutcome = syncOutcome
    }

    func setCiphersError(_ e: Error?) { ciphersError = e }
    func setRecentItemsError(_ error: Error?) { recentItemsError = error }
    func setSearchError(_ e: Error?) { searchError = e }
    func setSyncError(_ e: Error?) { syncError = e }
    func setOutboxStatus(_ status: VaultOutboxStatus) { outboxSnapshot = status }
    func setOutboxReadError(_ error: Error?) { outboxReadError = error }
    func setStored(_ c: [PlaintextCipher]) { stored = c }
    func beforeNextListing(_ hook: @escaping @Sendable () async -> Void) { listingHook = hook }
    func beforeNextOutboxRead(_ hook: @escaping @Sendable () async -> Void) { outboxReadHook = hook }

    func ciphers() async throws -> [PlaintextCipher] {
        ciphersCallCount += 1
        if let ciphersError { throw ciphersError }
        return stored.filter { $0.deletedDate == nil && $0.archivedDate == nil }
    }

    func cipher(id: String) async throws -> PlaintextCipher {
        guard let cipher = stored.first(where: { $0.id == id && $0.deletedDate == nil && $0.archivedDate == nil }) else {
            throw RepositoryError.cipherNotFound
        }
        return cipher
    }

    func search(_ query: String) async throws -> [PlaintextCipher] {
        searchQueries.append(query)
        if let searchError { throw searchError }
        let q = query.lowercased()
        return stored.filter { cipher in
            cipher.deletedDate == nil && cipher.archivedDate == nil && (
                cipher.name.lowercased().contains(q) || (cipher.login?.username?.lowercased().contains(q) ?? false)
                || (cipher.login?.uris.contains { $0.uri.lowercased().contains(q) } ?? false)
            )
        }
    }

    func createCipher(_ cipher: PlaintextCipher) async throws -> String {
        createdCiphers.append(cipher)
        let id = cipher.id ?? "new-\(createdCiphers.count)"
        var inserted = cipher
        inserted.id = id
        stored.append(inserted)
        return id
    }

    func exportArchive(for lease: AccountSessionLease) async throws -> VaultTransferArchive {
        if let ciphersError { throw ciphersError }
        return VaultTransferArchive(folders: storedFolders,
                                    items: stored.filter { $0.organizationID == nil && $0.deletedDate == nil })
    }

    func importCiphers(_ items: [PlaintextCipher], for lease: AccountSessionLease) async throws {
        for item in items { _ = try await createCipher(item) }
    }

    func importFolder(name: String, for lease: AccountSessionLease) async throws -> String {
        try await createFolder(name: name)
    }

    func updateCipher(id: String, _ cipher: PlaintextCipher) async throws {
        if let idx = stored.firstIndex(where: { $0.id == id }) { stored[idx] = cipher }
    }

    func archivedCiphers() async throws -> [PlaintextCipher] { stored.filter { $0.archivedDate != nil && $0.deletedDate == nil } }
    func listing() async throws -> VaultListing {
        if let listingHook {
            self.listingHook = nil
            await listingHook()
        }
        let active = try await ciphers()
        let archived = try await archivedCiphers()
        let trash = try await trashedCiphers()
        return VaultListing(active: active, archived: archived, trash: trash, folders: storedFolders)
    }
    func trashedCiphers() async throws -> [PlaintextCipher] { stored.filter { $0.deletedDate != nil } }
    func folders() async throws -> [PlaintextFolder] { storedFolders }

    func createFolder(name: String) async throws -> String {
        let folder = PlaintextFolder(id: UUID().uuidString, name: name)
        storedFolders.append(folder)
        return folder.id
    }

    func renameFolder(id: String, name: String) async throws {
        guard let index = storedFolders.firstIndex(where: { $0.id == id }) else { throw RepositoryError.cipherNotFound }
        storedFolders[index] = PlaintextFolder(id: id, name: name)
    }

    func deleteFolder(id: String) async throws {
        storedFolders.removeAll { $0.id == id }
        for index in stored.indices where stored[index].folderID == id { stored[index].folderID = nil }
    }

    func archiveCipher(id: String) async throws { stored[try index(for: id)].archivedDate = Date() }
    func unarchiveCipher(id: String) async throws { stored[try index(for: id)].archivedDate = nil }
    func trashCipher(id: String) async throws { stored[try index(for: id)].deletedDate = Date() }
    func restoreCipher(id: String) async throws { stored[try index(for: id)].deletedDate = nil }

    private func index(for id: String) throws -> Int {
        guard let index = stored.firstIndex(where: { $0.id == id }) else { throw RepositoryError.cipherNotFound }
        return index
    }

    func permanentlyDeleteCipher(id: String) async throws {
        guard stored[try index(for: id)].deletedDate != nil else { throw RepositoryError.cipherNotFound }
        deletedIDs.append(id)
        stored.removeAll { $0.id == id }
    }

    func sync() async throws -> SyncOutcome {
        syncCallCount += 1
        if let syncError { throw syncError }
        return syncOutcome
    }

    func outboxStatus(for session: AccountSessionLease?) async throws -> VaultOutboxStatus {
        outboxRequests.append(session)
        if let outboxReadHook {
            self.outboxReadHook = nil
            await outboxReadHook()
        }
        if let outboxReadError { throw outboxReadError }
        return outboxSnapshot
    }

    func resolveOutboxIssue(_ issue: VaultOutboxIssue, action: VaultOutboxAction,
                            for session: AccountSessionLease?) async throws {
        guard outboxSnapshot.issues.contains(where: { $0.id == issue.id }) else {
            throw RepositoryError.cipherChanged
        }
        let remaining = outboxSnapshot.issues.filter { $0.id != issue.id }
        switch action {
        case .useServer:
            outboxSnapshot = VaultOutboxStatus(pendingCount: outboxSnapshot.pendingCount, issues: remaining)
        case .keepLocalCopy:
            guard issue.canKeepLocalCopy else { throw RepositoryError.cipherChanged }
            outboxSnapshot = VaultOutboxStatus(pendingCount: outboxSnapshot.pendingCount + 1, issues: remaining)
        }
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
