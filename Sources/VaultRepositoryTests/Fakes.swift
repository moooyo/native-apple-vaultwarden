import Foundation
import CryptoCore
import VaultModels
import Networking
import SyncEngine
import VaultRepository

// MARK: - Combined fake API (AuthAPI + VaultAPI)

/// One in-memory fake implementing both `AuthAPI` (prelogin/token/refresh) and
/// `SyncEngine.VaultAPI` (sync/cipher CRUD/folders), so it can back the `AuthRepository`,
/// the `SyncEngine`, and the `VaultRepository` in a single test wiring. It records calls
/// and returns canned responses / throws canned errors.
actor FakeAPI: AuthAPI, VaultAPI {
    // Auth canned responses.
    var preloginResponse: PreloginResponse
    var tokenResults: [TokenResult]      // consumed FIFO (first = initial token, next = 2FA retry)
    var refreshResponse: TokenResponse?

    // Vault canned responses.
    var syncResponse: SyncResponse?
    var folderList: [FolderResponse] = []
    var createReturn: CipherResponse?
    var updateReturn: CipherResponse?
    var createError: Error?
    var updateError: Error?
    var deleteError: Error?
    var scopedAccessTokenError: Error?

    // Recording.
    private(set) var preloginCalls: [String] = []
    private(set) var environmentsSet: [ServerEnvironment] = []
    private(set) var environmentsAtPrelogin: [ServerEnvironment?] = []
    private(set) var tokenCalls: [(email: String, hash: String,
                                   twoFactor: TwoFactorPayload?, server: ServerEnvironment)] = []
    private(set) var accessTokensSet: [String?] = []
    private(set) var refreshTokensUsed: [String] = []
    private(set) var refreshServers: [ServerEnvironment] = []
    private(set) var emailCodeRequests: [(email: String, hash: String,
                                          server: ServerEnvironment)] = []
    private(set) var createdRequests: [CipherRequest] = []
    private(set) var updatedRequests: [(id: String, req: CipherRequest)] = []
    private(set) var deletedIDs: [String] = []
    private(set) var syncCallCount = 0

    init(preloginResponse: PreloginResponse, tokenResults: [TokenResult]) {
        self.preloginResponse = preloginResponse
        self.tokenResults = tokenResults
    }

    func setSyncResponse(_ r: SyncResponse) { syncResponse = r }
    func setCreateError(_ e: Error?) { createError = e }
    func setUpdateError(_ e: Error?) { updateError = e }
    func setDeleteError(_ e: Error?) { deleteError = e }
    func setRefreshResponse(_ r: TokenResponse?) { refreshResponse = r }
    func setScopedAccessTokenError(_ error: Error?) { scopedAccessTokenError = error }

    // AuthAPI.
    private var currentEnvironment: ServerEnvironment?
    private var currentAccountID: String?
    private var currentAuthenticationContextID: UUID?
    private var shouldPauseNextPrelogin = false
    private var preloginIsPaused = false
    private var pausedPreloginContinuation: CheckedContinuation<Void, Never>?
    private var preloginPauseObservers: [CheckedContinuation<Void, Never>] = []
    private var environmentCallCount = 0
    private var environmentCallToPause: Int?
    private var environmentCallIsPaused = false
    private var pausedEnvironmentContinuation: CheckedContinuation<Void, Never>?
    private var environmentPauseObservers: [CheckedContinuation<Void, Never>] = []
    private var shouldPauseNextCreate = false
    private var createIsPaused = false
    private var pausedCreateContinuation: CheckedContinuation<Void, Never>?
    private var createPauseObservers: [CheckedContinuation<Void, Never>] = []
    private var shouldPauseNextRefresh = false
    private var refreshIsPaused = false
    private var pausedRefreshContinuation: CheckedContinuation<Void, Never>?
    private var refreshPauseObservers: [CheckedContinuation<Void, Never>] = []
    private var shouldPauseNextSync = false
    private var syncIsPaused = false
    private var pausedSyncContinuation: CheckedContinuation<Void, Never>?
    private var syncPauseObservers: [CheckedContinuation<Void, Never>] = []
    private var shouldPauseNextToken = false
    private var tokenIsPaused = false
    private var pausedTokenContinuation: CheckedContinuation<Void, Never>?
    private var tokenPauseObservers: [CheckedContinuation<Void, Never>] = []
    private var shouldPauseNextAccountClear = false
    private var accountClearIsPaused = false
    private var pausedAccountClearContinuation: CheckedContinuation<Void, Never>?
    private var accountClearPauseObservers: [CheckedContinuation<Void, Never>] = []

    func setEnvironment(_ environment: ServerEnvironment) async {
        environmentCallCount += 1
        if environmentCallToPause == environmentCallCount {
            environmentCallToPause = nil
            environmentCallIsPaused = true
            let observers = environmentPauseObservers
            environmentPauseObservers.removeAll()
            observers.forEach { $0.resume() }
            await withCheckedContinuation { continuation in
                pausedEnvironmentContinuation = continuation
            }
        }
        currentEnvironment = environment
        currentAccountID = nil
        currentAuthenticationContextID = nil
        environmentsSet.append(environment)
        // Mirror APIClient's contract: applying an environment clears the old bearer.
        accessTokensSet.append(nil)
    }

    func setAccountID(_ accountID: String?) async {
        currentAccountID = accountID
        currentAuthenticationContextID = nil
    }

    func bindAccount(_ accountID: String, contextID: UUID) async {
        currentAccountID = accountID
        currentAuthenticationContextID = contextID
    }

    func pauseEnvironmentCall(_ call: Int) {
        environmentCallToPause = call
    }

    func waitUntilEnvironmentCallIsPaused() async {
        if environmentCallIsPaused { return }
        await withCheckedContinuation { continuation in
            environmentPauseObservers.append(continuation)
        }
    }

    func resumePausedEnvironmentCall() {
        environmentCallIsPaused = false
        let continuation = pausedEnvironmentContinuation
        pausedEnvironmentContinuation = nil
        continuation?.resume()
    }

    func pauseNextPrelogin() {
        shouldPauseNextPrelogin = true
    }

    func waitUntilPreloginIsPaused() async {
        if preloginIsPaused { return }
        await withCheckedContinuation { continuation in
            preloginPauseObservers.append(continuation)
        }
    }

    func resumePausedPrelogin() {
        preloginIsPaused = false
        let continuation = pausedPreloginContinuation
        pausedPreloginContinuation = nil
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

    func pauseNextRefresh() { shouldPauseNextRefresh = true }

    func waitUntilRefreshIsPaused() async {
        if refreshIsPaused { return }
        await withCheckedContinuation { refreshPauseObservers.append($0) }
    }

    func resumePausedRefresh() {
        refreshIsPaused = false
        let continuation = pausedRefreshContinuation
        pausedRefreshContinuation = nil
        continuation?.resume()
    }

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

    func pauseNextToken() { shouldPauseNextToken = true }

    func waitUntilTokenIsPaused() async {
        if tokenIsPaused { return }
        await withCheckedContinuation { tokenPauseObservers.append($0) }
    }

    func resumePausedToken() {
        tokenIsPaused = false
        let continuation = pausedTokenContinuation
        pausedTokenContinuation = nil
        continuation?.resume()
    }

    func pauseNextAccountClear() { shouldPauseNextAccountClear = true }

    func waitUntilAccountClearIsPaused() async {
        if accountClearIsPaused { return }
        await withCheckedContinuation { accountClearPauseObservers.append($0) }
    }

    func resumePausedAccountClear() {
        accountClearIsPaused = false
        let continuation = pausedAccountClearContinuation
        pausedAccountClearContinuation = nil
        continuation?.resume()
    }

    func prelogin(email: String, server: ServerEnvironment) async throws -> PreloginResponse {
        preloginCalls.append(email)
        environmentsAtPrelogin.append(server)
        if shouldPauseNextPrelogin {
            shouldPauseNextPrelogin = false
            preloginIsPaused = true
            let observers = preloginPauseObservers
            preloginPauseObservers.removeAll()
            observers.forEach { $0.resume() }
            await withCheckedContinuation { continuation in
                pausedPreloginContinuation = continuation
            }
        }
        return preloginResponse
    }

    func token(email: String, passwordHash: String, twoFactor: TwoFactorPayload?,
               server: ServerEnvironment) async throws -> TokenResult {
        tokenCalls.append((email, passwordHash, twoFactor, server))
        if shouldPauseNextToken {
            shouldPauseNextToken = false
            tokenIsPaused = true
            let observers = tokenPauseObservers
            tokenPauseObservers.removeAll()
            observers.forEach { $0.resume() }
            await withCheckedContinuation { pausedTokenContinuation = $0 }
        }
        guard !tokenResults.isEmpty else { fatalError("FakeAPI: no token result queued") }
        return tokenResults.removeFirst()
    }

    func sendEmailLoginCode(email: String, masterPasswordHash: String,
                            server: ServerEnvironment) async throws {
        emailCodeRequests.append((email, masterPasswordHash, server))
    }

    func refresh(refreshToken: String, server: ServerEnvironment,
                 accountID: String) async throws -> TokenResponse {
        try requireAccount(accountID)
        refreshTokensUsed.append(refreshToken)
        refreshServers.append(server)
        if shouldPauseNextRefresh {
            shouldPauseNextRefresh = false
            refreshIsPaused = true
            let observers = refreshPauseObservers
            refreshPauseObservers.removeAll()
            observers.forEach { $0.resume() }
            await withCheckedContinuation { pausedRefreshContinuation = $0 }
        }
        guard let refreshResponse else { throw NetworkingError.unauthorized }
        accessTokensSet.append(refreshResponse.accessToken)
        return refreshResponse
    }

    func setAccessToken(_ token: String?) async { accessTokensSet.append(token) }

    func setAccessToken(_ token: String?, for accountID: String) async throws {
        guard currentAccountID == accountID else {
            throw NetworkingError.accountContextChanged
        }
        if let scopedAccessTokenError { throw scopedAccessTokenError }
        accessTokensSet.append(token)
    }

    func clearAccountContext(accountID: String, contextID: UUID) async {
        if shouldPauseNextAccountClear {
            shouldPauseNextAccountClear = false
            accountClearIsPaused = true
            let observers = accountClearPauseObservers
            accountClearPauseObservers.removeAll()
            observers.forEach { $0.resume() }
            await withCheckedContinuation { pausedAccountClearContinuation = $0 }
        }
        guard currentAccountID == accountID,
              currentAuthenticationContextID == contextID else { return }
        currentAccountID = nil
        currentAuthenticationContextID = nil
        accessTokensSet.append(nil)
    }

    // VaultAPI.
    func sync(accountID: String, excludeDomains: Bool) async throws -> SyncResponse {
        try requireAccount(accountID)
        syncCallCount += 1
        if shouldPauseNextSync {
            shouldPauseNextSync = false
            syncIsPaused = true
            let observers = syncPauseObservers
            syncPauseObservers.removeAll()
            observers.forEach { $0.resume() }
            await withCheckedContinuation { pausedSyncContinuation = $0 }
        }
        guard let syncResponse else { throw NetworkingError.serverUnreachable }
        return syncResponse
    }

    func createCipher(accountID: String, _ req: CipherRequest) async throws -> CipherResponse {
        try requireAccount(accountID)
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
        return createReturn ?? Self.echo(req, id: "server-id-\(createdRequests.count)")
    }

    func updateCipher(accountID: String, id: String, _ req: CipherRequest) async throws -> CipherResponse {
        try requireAccount(accountID)
        updatedRequests.append((id, req))
        if let updateError { throw updateError }
        return updateReturn ?? Self.echo(req, id: id)
    }

    func deleteCipher(accountID: String, id: String) async throws {
        try requireAccount(accountID)
        deletedIDs.append(id)
        if let deleteError { throw deleteError }
    }

    func folders(accountID: String) async throws -> [FolderResponse] {
        try requireAccount(accountID)
        return folderList
    }

    private func requireAccount(_ accountID: String) throws {
        guard currentAccountID == accountID else {
            throw NetworkingError.accountContextChanged
        }
    }

    static func echo(_ req: CipherRequest, id: String) -> CipherResponse {
        let login = req.login.map { l in
            LoginModel(username: l.username, password: l.password, totp: l.totp,
                       uris: l.uris?.map { LoginUriModel(uri: $0.uri, match: $0.match.map(UriMatchType.init(rawValue:))) },
                       fido2Credentials: l.fido2Credentials?.map {
                           Fido2CredentialModel(
                               credentialId: $0.credentialId, keyType: $0.keyType,
                               keyAlgorithm: $0.keyAlgorithm, keyCurve: $0.keyCurve,
                               keyValue: $0.keyValue, rpId: $0.rpId, rpName: $0.rpName,
                               userHandle: $0.userHandle, userName: $0.userName,
                               userDisplayName: $0.userDisplayName, counter: $0.counter,
                               discoverable: $0.discoverable, creationDate: $0.creationDate
                           )
                       },
                       passwordRevisionDate: l.passwordRevisionDate)
        }
        let card = req.card.map {
            CardModel(cardholderName: $0.cardholderName, brand: $0.brand,
                      number: $0.number, expMonth: $0.expMonth,
                      expYear: $0.expYear, code: $0.code)
        }
        let identity = req.identity.map {
            IdentityModel(
                title: $0.title, firstName: $0.firstName, middleName: $0.middleName,
                lastName: $0.lastName, address1: $0.address1, address2: $0.address2,
                address3: $0.address3, city: $0.city, state: $0.state,
                postalCode: $0.postalCode, country: $0.country, company: $0.company,
                email: $0.email, phone: $0.phone, ssn: $0.ssn, username: $0.username,
                passportNumber: $0.passportNumber, licenseNumber: $0.licenseNumber
            )
        }
        let secureNote = req.secureNote.map { SecureNoteModel(type: SecureNoteType(rawValue: $0.type)) }
        let sshKey = req.sshKey.map {
            SshKeyModel(privateKey: $0.privateKey, publicKey: $0.publicKey,
                        keyFingerprint: $0.keyFingerprint)
        }
        let fields = req.fields?.map {
            FieldModel(type: FieldType(rawValue: $0.type), name: $0.name,
                       value: $0.value, linkedId: $0.linkedId)
        }
        return CipherResponse(
            id: id, organizationId: req.organizationId, folderId: req.folderId,
            type: CipherType(rawValue: req.type), name: req.name, notes: req.notes,
            favorite: req.favorite, reprompt: req.reprompt, edit: true, viewPassword: true,
            login: login, card: card, identity: identity, secureNote: secureNote, sshKey: sshKey,
            fields: fields, attachments: nil, collectionIds: nil, key: req.key,
            revisionDate: Date(), creationDate: Date(), deletedDate: nil
        )
    }
}

// MARK: - Fake identity store (for the SyncEngine the VaultRepository drives)

actor FakeIdentityStore: CredentialIdentityWriting {
    var enabled: Bool
    var incrementalSupported: Bool
    private(set) var replaceAllCalls = 0
    private(set) var lastReplaceAll: [CredentialIdentity] = []

    init(enabled: Bool = false, incrementalSupported: Bool = false) {
        self.enabled = enabled
        self.incrementalSupported = incrementalSupported
    }
    func isEnabled() async -> Bool { enabled }
    func supportsIncremental() async -> Bool { incrementalSupported }
    func replaceAll(_ identities: [CredentialIdentity]) async {
        replaceAllCalls += 1; lastReplaceAll = identities
    }
    func incremental(add: [CredentialIdentity], remove: [CredentialIdentity]) async {}
}
