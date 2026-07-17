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

    // Recording.
    private(set) var preloginCalls: [String] = []
    private(set) var environmentsSet: [ServerEnvironment] = []
    private(set) var tokenCalls: [(email: String, hash: String, twoFactor: TwoFactorPayload?)] = []
    private(set) var accessTokensSet: [String?] = []
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

    // AuthAPI.
    func setEnvironment(_ environment: ServerEnvironment) async {
        environmentsSet.append(environment)
    }

    func prelogin(email: String) async throws -> PreloginResponse {
        preloginCalls.append(email)
        return preloginResponse
    }

    func token(email: String, passwordHash: String, twoFactor: TwoFactorPayload?) async throws -> TokenResult {
        tokenCalls.append((email, passwordHash, twoFactor))
        guard !tokenResults.isEmpty else { fatalError("FakeAPI: no token result queued") }
        return tokenResults.removeFirst()
    }

    func refresh(refreshToken: String) async throws -> TokenResponse {
        guard let refreshResponse else { throw NetworkingError.unauthorized }
        return refreshResponse
    }

    func setAccessToken(_ token: String?) async { accessTokensSet.append(token) }

    // VaultAPI.
    func sync(excludeDomains: Bool) async throws -> SyncResponse {
        syncCallCount += 1
        guard let syncResponse else { throw NetworkingError.serverUnreachable }
        return syncResponse
    }

    func createCipher(_ req: CipherRequest) async throws -> CipherResponse {
        createdRequests.append(req)
        if let createError { throw createError }
        return createReturn ?? Self.echo(req, id: "server-id-\(createdRequests.count)")
    }

    func updateCipher(id: String, _ req: CipherRequest) async throws -> CipherResponse {
        updatedRequests.append((id, req))
        if let updateError { throw updateError }
        return updateReturn ?? Self.echo(req, id: id)
    }

    func deleteCipher(id: String) async throws {
        deletedIDs.append(id)
        if let deleteError { throw deleteError }
    }

    func folders() async throws -> [FolderResponse] { folderList }

    static func echo(_ req: CipherRequest, id: String) -> CipherResponse {
        let login = req.login.map { l in
            LoginModel(username: l.username, password: l.password, totp: l.totp,
                       uris: l.uris?.map { LoginUriModel(uri: $0.uri, match: $0.match.map(UriMatchType.init(rawValue:))) },
                       fido2Credentials: nil, passwordRevisionDate: nil)
        }
        return CipherResponse(
            id: id, organizationId: req.organizationId, folderId: req.folderId,
            type: CipherType(rawValue: req.type), name: req.name, notes: req.notes,
            favorite: req.favorite, reprompt: req.reprompt, edit: true, viewPassword: true,
            login: login, card: nil, identity: nil, secureNote: nil, sshKey: nil,
            fields: nil, attachments: nil, collectionIds: nil, key: req.key,
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
