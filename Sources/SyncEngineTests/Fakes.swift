import Foundation
import VaultModels
import Networking
import SyncEngine

// MARK: - Fake VaultAPI

/// An in-memory `VaultAPI` for tests: returns a canned `SyncResponse`, records every
/// create/update/delete call, and can be told to throw a canned error on a given
/// operation (to exercise conflict/soft-fail paths).
actor FakeVaultAPI: VaultAPI {
    var syncResponse: SyncResponse
    var folderList: [FolderResponse] = []

    /// Error to throw from `createCipher` (e.g. an HTTP 400 conflict). `nil` → succeed.
    var createError: Error?
    var updateError: Error?
    var deleteError: Error?

    /// The cipher returned by a successful create/update (defaults to echoing a row).
    var createReturn: CipherResponse?
    var updateReturn: CipherResponse?

    // Call recording.
    private(set) var createdRequests: [CipherRequest] = []
    private(set) var updatedRequests: [(id: String, req: CipherRequest)] = []
    private(set) var deletedIDs: [String] = []
    private(set) var syncCallCount = 0
    private var shouldPauseNextSync = false
    private var syncIsPaused = false
    private var pausedSyncContinuation: CheckedContinuation<Void, Never>?
    private var syncPauseObservers: [CheckedContinuation<Void, Never>] = []
    private var shouldPauseNextCreate = false
    private var createIsPaused = false
    private var pausedCreateContinuation: CheckedContinuation<Void, Never>?
    private var createPauseObservers: [CheckedContinuation<Void, Never>] = []

    init(syncResponse: SyncResponse) {
        self.syncResponse = syncResponse
    }

    func setSyncResponse(_ r: SyncResponse) { syncResponse = r }
    func setCreateError(_ e: Error?) { createError = e }
    func setUpdateError(_ e: Error?) { updateError = e }
    func setDeleteError(_ e: Error?) { deleteError = e }
    func setCreateReturn(_ c: CipherResponse?) { createReturn = c }
    func setUpdateReturn(_ c: CipherResponse?) { updateReturn = c }
    func pauseNextSync() { shouldPauseNextSync = true }
    func waitUntilSyncIsPaused() async {
        if syncIsPaused { return }
        await withCheckedContinuation { syncPauseObservers.append($0) }
    }
    func resumePausedSync() {
        syncIsPaused = false
        let continuation = pausedSyncContinuation
        pausedSyncContinuation = nil
        continuation?.resume()
    }
    func pauseNextCreate() { shouldPauseNextCreate = true }
    func waitUntilCreateIsPaused() async {
        if createIsPaused { return }
        await withCheckedContinuation { createPauseObservers.append($0) }
    }
    func resumePausedCreate() {
        createIsPaused = false
        let continuation = pausedCreateContinuation
        pausedCreateContinuation = nil
        continuation?.resume()
    }

    func sync(accountID: String, excludeDomains: Bool) async throws -> SyncResponse {
        syncCallCount += 1
        if shouldPauseNextSync {
            shouldPauseNextSync = false
            syncIsPaused = true
            let observers = syncPauseObservers
            syncPauseObservers.removeAll()
            observers.forEach { $0.resume() }
            await withCheckedContinuation { pausedSyncContinuation = $0 }
        }
        return syncResponse
    }

    func createCipher(accountID: String, _ req: CipherRequest) async throws -> CipherResponse {
        createdRequests.append(req)
        if shouldPauseNextCreate {
            shouldPauseNextCreate = false
            createIsPaused = true
            let observers = createPauseObservers
            createPauseObservers.removeAll()
            observers.forEach { $0.resume() }
            await withCheckedContinuation { pausedCreateContinuation = $0 }
        }
        if let createError { throw createError }
        return createReturn ?? Self.echoCipher(from: req, id: "server-generated-id")
    }

    func updateCipher(accountID: String, id: String, _ req: CipherRequest) async throws -> CipherResponse {
        updatedRequests.append((id, req))
        if let updateError { throw updateError }
        return updateReturn ?? Self.echoCipher(from: req, id: id)
    }

    func deleteCipher(accountID: String, id: String) async throws {
        deletedIDs.append(id)
        if let deleteError { throw deleteError }
    }

    func folders(accountID: String) async throws -> [FolderResponse] { folderList }

    /// Build a minimal `CipherResponse` echoing a request (server would fill dates/id).
    private static func echoCipher(from req: CipherRequest, id: String) -> CipherResponse {
        CipherResponse(
            id: id,
            organizationId: req.organizationId,
            folderId: req.folderId,
            type: CipherType(rawValue: req.type),
            name: req.name,
            notes: req.notes,
            favorite: req.favorite,
            reprompt: req.reprompt,
            edit: true,
            viewPassword: true,
            login: nil,
            card: nil,
            identity: nil,
            secureNote: nil,
            sshKey: nil,
            fields: nil,
            attachments: nil,
            collectionIds: nil,
            key: req.key,
            revisionDate: Date(),
            creationDate: Date(),
            deletedDate: nil
        )
    }
}

// MARK: - Fake CredentialIdentityWriting

/// An in-memory `CredentialIdentityWriting` for tests. Records which API path was used
/// (replaceAll vs incremental) and the identities passed, with configurable
/// enabled/supportsIncremental flags.
actor FakeIdentityStore: CredentialIdentityWriting {
    var enabled: Bool
    var incrementalSupported: Bool

    private(set) var replaceAllCalls = 0
    private(set) var incrementalCalls = 0
    private(set) var lastReplaceAll: [CredentialIdentity] = []
    private(set) var lastIncrementalAdd: [CredentialIdentity] = []
    private(set) var lastIncrementalRemove: [CredentialIdentity] = []

    init(enabled: Bool = true, incrementalSupported: Bool = false) {
        self.enabled = enabled
        self.incrementalSupported = incrementalSupported
    }

    func isEnabled() async -> Bool { enabled }
    func supportsIncremental() async -> Bool { incrementalSupported }

    func replaceAll(_ identities: [CredentialIdentity]) async {
        replaceAllCalls += 1
        lastReplaceAll = identities
    }

    func incremental(add: [CredentialIdentity], remove: [CredentialIdentity]) async {
        incrementalCalls += 1
        lastIncrementalAdd = add
        lastIncrementalRemove = remove
    }
}
