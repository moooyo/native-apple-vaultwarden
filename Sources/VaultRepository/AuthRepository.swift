import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import KeychainBridge
import Networking
import AppShared

/// App-facing authentication + unlock orchestration (design spec §5.9 / §6).
///
/// Owns the login → KDF → token → unlock pipeline, the 2FA round-trip, and the
/// persistence of the refresh token + offline local-auth hash. PBKDF2-only (D6): a
/// non-PBKDF2 account is rejected with a clear `RepositoryError.unsupportedKDF` before any
/// key material is derived.
///
/// An `actor` so the in-flight login state (pending KDF / hash across the 2FA retry) and
/// the current session are serialized.
public actor AuthRepository {
    private let api: AuthAPI
    private let keyVault: KeyVault
    private let keychain: KeychainBridge
    private let store: VaultStore
    private let encryptor: VaultEncrypting

    /// The active session after a successful login (account id, email, KDF iters,
    /// protected user key). `nil` until login succeeds / after `logout`.
    public private(set) var session: AccountSession?
    /// Distinguishes successive incarnations of the same canonical account (ABA guard).
    private var sessionGeneration: UInt64 = 0
    /// Mirrors the unique owner installed in `AuthAPI` for the published session.
    private var sessionAuthenticationContextID: UUID?

    /// In-flight login state retained between the first `login` and a `submitTwoFactor`
    /// retry: the credentials + derived hashes so the retry doesn't re-run the KDF.
    private struct PendingLogin: Sendable {
        let attemptID: UUID
        let email: String
        let password: String
        let iterations: Int
        let serverHash: String
        let localHash: String
        /// The server that produced the prelogin/KDF parameters. A 2FA retry must use
        /// this exact environment; switching servers mid-challenge is rejected.
        let server: ServerEnvironment
    }
    private var pending: PendingLogin?
    private var currentLoginAttemptID: UUID?
    private var currentLoginIntentGeneration: UInt64 = 0
    private var authenticationIntentGeneration: UInt64 = 0
    private var activeTwoFactorSubmissionID: UUID?
    private var isCompletingLogin = false
    /// Lets logout remove secrets already written by a commit before its session is published.
    private var completingAccountID: String?
    private var completingAuthenticationContextID: UUID?
    private var isLocking = false
    private var isTransitioningAuthentication = false
    /// Durable-in-actor ownership for logout cleanup after `session` has been withdrawn.
    /// A duplicate logout can take this lease over; a real new login explicitly discards it.
    private struct LogoutCleanupLease: Sendable {
        let id: UUID
        let accountID: String
        let authenticationContextID: UUID?
    }
    private var pendingLogoutCleanup: LogoutCleanupLease?
    private let loginCommitCoordinator = AuthOperationCoordinator()
    private let sessionOperationCoordinator = AuthOperationCoordinator()
    private let biometricPolicyCoordinator = AuthOperationCoordinator()
    private var biometricPolicyGeneration: UInt64 = 0

    public init(api: AuthAPI, keyVault: KeyVault, keychain: KeychainBridge, store: VaultStore,
                encryptor: VaultEncrypting) {
        self.api = api
        self.keyVault = keyVault
        self.keychain = keychain
        self.store = store
        self.encryptor = encryptor
    }

    // MARK: - Login

    /// Reserve ordering before UI adapters perform asynchronous policy/identity work.
    public func reserveAuthenticationIntent() async -> UInt64 {
        authenticationIntentGeneration &+= 1
        biometricPolicyGeneration &+= 1
        isTransitioningAuthentication = true
        currentLoginAttemptID = nil
        activeTwoFactorSubmissionID = nil
        let generation = authenticationIntentGeneration
        await keychain.deleteSecret(account: AppShared.KeychainAccount.activeSessionID)
        if authenticationIntentGeneration == generation {
            await keychain.deleteSecret(account: AppShared.KeychainAccount.activeAccountID)
        }
        return generation
    }

    public func isAuthenticationIntentCurrent(_ generation: UInt64) -> Bool {
        authenticationIntentGeneration == generation
    }

    /// Run the full login pipeline for a PBKDF2 account.
    ///
    /// `prelogin` → **reject kdf != 0 (PBKDF2-only, D6)** → derive master key → server-auth
    /// hash → `token`. On success the protected user key is decrypted into the `KeyVault`,
    /// the refresh token + offline local-auth hash are persisted, and biometric unlock is
    /// enabled when `enableBiometrics` is set. A 2FA challenge returns
    /// `.twoFactorRequired`; the caller answers via `submitTwoFactor`.
    public func login(email: String, password: String, server: ServerEnvironment,
                      enableBiometrics: Bool = false,
                      reservedIntent: UInt64? = nil) async throws -> LoginResult {
        guard !isLocking else {
            if let reservedIntent,
               authenticationIntentGeneration == reservedIntent {
                isTransitioningAuthentication = false
            }
            throw RepositoryError.underlying(
                kind: .network,
                description: "The vault is being locked"
            )
        }
        let intentGeneration: UInt64
        if let reservedIntent {
            guard authenticationIntentGeneration == reservedIntent else {
                throw RepositoryError.underlying(
                    kind: .network,
                    description: "Authentication intent was superseded"
                )
            }
            intentGeneration = reservedIntent
        } else {
            authenticationIntentGeneration &+= 1
            biometricPolicyGeneration &+= 1
            intentGeneration = authenticationIntentGeneration
        }
        isTransitioningAuthentication = true
        let normalizedEmail = email.trimmingCharacters(in: .whitespacesAndNewlines)
        let attemptID = UUID()
        currentLoginAttemptID = attemptID
        currentLoginIntentGeneration = intentGeneration
        activeTwoFactorSubmissionID = nil

        do {
            // Beginning a real login (as opposed to merely reserving an intent) supersedes
            // any older logout cleanup. Its account/context-scoped operations must stop at
            // their next intent guard and must never be inherited by a later logout of the
            // new session.
            pendingLogoutCleanup = nil
            // A new login supersedes any outstanding 2FA challenge. Apply the user-entered
            // server before prelogin; APIClient also clears a bearer issued by the previous
            // environment as part of this operation.
            pending = nil
            session = nil
            sessionAuthenticationContextID = nil
            advanceSessionGeneration()
            // Withdraw the published account at the start of the transition. A failed or
            // suspended login must not leave the AutoFill extension able to vend the previous
            // account while the app has already abandoned that session.
            await keychain.deleteSecret(account: AppShared.KeychainAccount.activeAccountID)
            try requireCurrentLoginAttempt(attemptID)
            await keychain.deleteSecret(account: AppShared.KeychainAccount.activeSessionID)
            try requireCurrentLoginAttempt(attemptID)
            await api.setEnvironment(server)
            try requireCurrentLoginAttempt(attemptID)
            await keyVault.lock()
            try requireCurrentLoginAttempt(attemptID)
            await encryptor.clear()
            try requireCurrentLoginAttempt(attemptID)

            let prelogin: PreloginResponse
            do { prelogin = try await api.prelogin(email: normalizedEmail, server: server) }
            catch { throw RepositoryError.network(error) }
            try requireCurrentLoginAttempt(attemptID)

            // PBKDF2-only guard (D6): kdf == 0 is PBKDF2; anything else (1 = Argon2id) is rejected
            // with a clear error BEFORE any derivation.
            guard prelogin.kdf == 0 else { throw RepositoryError.unsupportedKDF(prelogin.kdf) }

            let masterKey: [UInt8]
            let serverHash: String
            let localHash: String
            do {
                masterKey = try KDF.deriveMasterKey(password: password, email: normalizedEmail,
                                                    iterations: prelogin.kdfIterations)
                serverHash = try KDF.masterPasswordHash(masterKey: masterKey, password: password,
                                                        purpose: .serverAuthorization)
                localHash = try KDF.masterPasswordHash(masterKey: masterKey, password: password,
                                                       purpose: .localAuthorization)
            } catch {
                throw RepositoryError.crypto(error)
            }

            let pending = PendingLogin(attemptID: attemptID, email: normalizedEmail,
                                       password: password,
                                       iterations: prelogin.kdfIterations,
                                       serverHash: serverHash, localHash: localHash,
                                       server: server)
            return try await requestToken(pending: pending, twoFactor: nil,
                                          enableBiometrics: enableBiometrics)
        } catch {
            finishLoginFailureIfCurrent(attemptID)
            throw error
        }
    }

    /// Answer a 2FA challenge with `provider` + `token`, retrying the token grant.
    /// Must be called after a `login` that returned `.twoFactorRequired`.
    public func submitTwoFactor(provider: TwoFactorProvider, token: String, remember: Bool = false,
                                server: ServerEnvironment, enableBiometrics: Bool = false) async throws -> LoginResult {
        guard let pending else { throw RepositoryError.notAuthenticated }
        guard activeTwoFactorSubmissionID == nil else {
            throw RepositoryError.underlying(
                kind: .network,
                description: "Another two-factor submission is in progress"
            )
        }
        let submissionID = UUID()
        activeTwoFactorSubmissionID = submissionID
        defer {
            if activeTwoFactorSubmissionID == submissionID {
                activeTwoFactorSubmissionID = nil
            }
        }
        try requireCurrentLoginAttempt(pending.attemptID)
        guard server == pending.server else {
            throw RepositoryError.underlying(
                kind: .network,
                description: "Server changed during two-factor authentication"
            )
        }
        let payload = TwoFactorPayload(provider: provider, token: token, remember: remember)
        return try await requestToken(pending: pending, twoFactor: payload,
                                      enableBiometrics: enableBiometrics)
    }

    /// Shared token-grant + post-success unlock/persist path.
    private func requestToken(pending: PendingLogin, twoFactor: TwoFactorPayload?,
                              enableBiometrics: Bool) async throws -> LoginResult {
        let result: TokenResult
        do {
            result = try await api.token(email: pending.email, passwordHash: pending.serverHash,
                                         twoFactor: twoFactor, server: pending.server)
        } catch {
            throw RepositoryError.network(error)
        }
        try requireCurrentLoginAttempt(pending.attemptID)

        switch result {
        case .twoFactorRequired(let providers):
            // Retain the derived hashes so the retry skips the KDF.
            self.pending = pending
            if providers.providers.count > 1 && providers.providers.contains(.email) {
                try? await api.sendEmailLoginCode(
                    email: pending.email,
                    masterPasswordHash: pending.serverHash,
                    server: pending.server
                )
                try requireCurrentLoginAttempt(pending.attemptID)
            }
            return .twoFactorRequired(providers.providers)

        case .success(let tokenResponse):
            try await loginCommitCoordinator.withLock {
                do {
                    try await self.completeLogin(
                        tokenResponse,
                        pending: pending,
                        enableBiometrics: enableBiometrics
                    )
                } catch {
                    await self.rollbackFailedLoginCommitIfCurrent(pending)
                    throw error
                }
            }
            try requireCurrentLoginAttempt(pending.attemptID)
            self.pending = nil
            currentLoginAttemptID = nil
            isTransitioningAuthentication = false
            return .success
        }
    }

    public func sendTwoFactorEmail(server: ServerEnvironment) async throws {
        guard let pending else { throw RepositoryError.notAuthenticated }
        try requireCurrentLoginAttempt(pending.attemptID)
        guard pending.server == server else { throw RepositoryError.notAuthenticated }
        do {
            try await api.sendEmailLoginCode(
                email: pending.email,
                masterPasswordHash: pending.serverHash,
                server: pending.server
            )
        } catch { throw RepositoryError.network(error) }
        try requireCurrentLoginAttempt(pending.attemptID)
    }

    /// Decrypt the protected user key, durably persist the account, then publish the new
    /// in-memory session. Persisting first avoids leaving a usable bearer/user key behind if
    /// the encrypted store rejects the account row.
    private func completeLogin(_ tokenResponse: TokenResponse, pending: PendingLogin,
                               enableBiometrics: Bool) async throws {
        try requireCurrentLoginAttempt(pending.attemptID)
        isCompletingLogin = true
        defer {
            isCompletingLogin = false
            completingAccountID = nil
            completingAuthenticationContextID = nil
        }
        guard let protectedKey = tokenResponse.key else { throw RepositoryError.missingUserKey }

        // Decrypt the protected user key locally so we hold the raw `SymmetricCryptoKey`
        // (needed to SE-wrap it for biometric unlock), then unlock the KeyVault directly.
        let userKey: SymmetricCryptoKey
        do {
            userKey = try Self.decryptUserKey(password: pending.password, email: pending.email,
                                              iterations: pending.iterations, protectedKey: protectedKey)
        } catch {
            throw RepositoryError.authenticationFailed
        }
        let accountID = Self.accountID(server: pending.server, email: pending.email)
        completingAccountID = accountID
        completingAuthenticationContextID = pending.attemptID
        // Withdraw the old account before changing any account-scoped persistence. If this
        // login is interrupted, no marker can pair one account's server with another token.
        await keychain.deleteSecret(account: AppShared.KeychainAccount.activeAccountID)
        try requireCurrentLoginAttempt(pending.attemptID)
        // Persist the account row (so sync + unlock can find it).
        let accountRow = AccountRow(
            id: accountID, email: pending.email, serverURL: pending.server.base.absoluteString,
            kdfType: 0, kdfIters: pending.iterations,
            encUserKey: protectedKey.stringValue,
            encPrivateKey: tokenResponse.privateKey?.stringValue
        )
        do { try await store.upsertAccounts([accountRow]) }
        catch { throw RepositoryError.store(error) }
        try requireCurrentLoginAttempt(pending.attemptID)

        // Remove any previous account's wrapped key before publishing the new active marker.
        // A crash can now disable biometric unlock, but can never bind this session to the
        // previous account's still-valid user key.
        await keychain.disableBiometricUnlock()
        try requireCurrentLoginAttempt(pending.attemptID)
        await keychain.deleteSecret(account: AppShared.KeychainAccount.biometricAccountID)
        try requireCurrentLoginAttempt(pending.attemptID)

        // Persist account-scoped secrets first, then publish the active marker last. Keychain
        // failure does not invalidate the current server login, but cold restoration remains
        // disabled rather than publishing a partially written identity.
        var canPublishActiveAccount = true
        if let refresh = tokenResponse.refreshToken {
            do {
                try await keychain.setSecret(
                    Data(refresh.utf8),
                    account: AppShared.KeychainAccount.refreshToken(accountID: accountID),
                    biometryGated: false
                )
            } catch {
                canPublishActiveAccount = false
            }
            try requireCurrentLoginAttempt(pending.attemptID)
        }
        do {
            try await keychain.setSecret(
                Data(pending.localHash.utf8),
                account: AppShared.KeychainAccount.localAuthHash(accountID: accountID),
                biometryGated: false
            )
        } catch {
            canPublishActiveAccount = false
        }
        try requireCurrentLoginAttempt(pending.attemptID)
        if canPublishActiveAccount {
            do {
                try await keychain.setSecret(
                    Data(UUID().uuidString.lowercased().utf8),
                    account: AppShared.KeychainAccount.activeSessionID,
                    biometryGated: false
                )
            } catch {
                canPublishActiveAccount = false
                await keychain.deleteSecret(
                    account: AppShared.KeychainAccount.activeSessionID
                )
            }
            try requireCurrentLoginAttempt(pending.attemptID)
        }
        if canPublishActiveAccount {
            do {
                try await keychain.setSecret(
                    Data(accountID.utf8),
                    account: AppShared.KeychainAccount.activeAccountID,
                    biometryGated: false
                )
            } catch {
                await keychain.deleteSecret(
                    account: AppShared.KeychainAccount.activeAccountID
                )
                await keychain.deleteSecret(
                    account: AppShared.KeychainAccount.activeSessionID
                )
            }
            try requireCurrentLoginAttempt(pending.attemptID)
        }
        // Never read these legacy global names again: they cannot be safely attributed when a
        // previous write was interrupted during an account switch.
        await keychain.deleteSecret(account: AppShared.KeychainAccount.legacyRefreshToken)
        try requireCurrentLoginAttempt(pending.attemptID)
        await keychain.deleteSecret(account: AppShared.KeychainAccount.legacyLocalAuthHash)
        try requireCurrentLoginAttempt(pending.attemptID)

        await keyVault.unlock(userKey: userKey)
        try requireCurrentLoginAttempt(pending.attemptID)
        await encryptor.setUserKey(userKey)
        try requireCurrentLoginAttempt(pending.attemptID)

        // Bind server/bearer to this canonical account. A superseding login revokes the
        // lease, so this scoped setter cannot install a stale token on another server.
        await api.setEnvironment(pending.server)
        try requireCurrentLoginAttempt(pending.attemptID)
        await api.bindAccount(accountID, contextID: pending.attemptID)
        try requireCurrentLoginAttempt(pending.attemptID)
        do { try await api.setAccessToken(tokenResponse.accessToken, for: accountID) }
        catch { throw RepositoryError.network(error) }
        try requireCurrentLoginAttempt(pending.attemptID)

        // Publish only after the API's server/account/bearer triple is ready. Callers that
        // observe a session can therefore never start sync against a half-bound context.
        sessionAuthenticationContextID = pending.attemptID
        self.session = AccountSession(
            accountID: accountID,
            email: pending.email,
            kdfIterations: pending.iterations,
            protectedUserKey: protectedKey.stringValue
        )

        // Replace any previous account's biometric material. Leaving it in place when the
        // current policy is disabled could otherwise unlock this session with the wrong key.
        if enableBiometrics {
            do {
                try await keychain.enableBiometricUnlock(userKey: userKey)
                try requireCurrentLoginAttempt(pending.attemptID)
                try await keychain.setSecret(
                    Data(accountID.utf8),
                    account: AppShared.KeychainAccount.biometricAccountID,
                    biometryGated: false
                )
            } catch {
                await keychain.disableBiometricUnlock()
                await keychain.deleteSecret(
                    account: AppShared.KeychainAccount.biometricAccountID
                )
            }
            try requireCurrentLoginAttempt(pending.attemptID)
        }
    }

    // MARK: - Cold-start restoration

    /// Rehydrate the last active account into a locked in-memory session.
    ///
    /// Only the account identifier lives in the shared Keychain; all session metadata comes
    /// from the encrypted store. The API environment is restored before the session becomes
    /// visible, and no user key or bearer token is loaded. Returns the canonical server URL
    /// when restoration succeeds so the app can keep its settings display in sync.
    @discardableResult
    public func restoreSession() async throws -> String? {
        if let existingSession = session {
            let generation = sessionGeneration
            let account = try await store.account(id: existingSession.accountID)
            try requireCurrentSession(
                accountID: existingSession.accountID,
                generation: generation
            )
            if let serverURL = account?.serverURL {
                return serverURL
            }
        }

        let restoreGeneration = sessionGeneration
        try requireRestoreLease(generation: restoreGeneration)

        let marker: Data?
        do {
            marker = try await keychain.getSecret(
                account: AppShared.KeychainAccount.activeAccountID
            )
        } catch {
            throw RepositoryError.store(error)
        }
        try requireRestoreLease(generation: restoreGeneration)
        guard let marker,
              let accountID = String(data: marker, encoding: .utf8),
              !accountID.isEmpty else {
            return nil
        }

        let account: AccountRow?
        do { account = try await store.account(id: accountID) }
        catch { throw RepositoryError.store(error) }
        try requireRestoreLease(generation: restoreGeneration)

        guard let account,
              account.kdfType == 0,
              let email = account.email, !email.isEmpty,
              let iterations = account.kdfIters, iterations > 0,
              let protectedUserKey = account.encUserKey,
              (try? EncString(parsing: protectedUserKey)) != nil,
              let serverURL = account.serverURL,
              let server = ServerEnvironment(string: serverURL),
              // Pre-canonical releases keyed rows as `host|email`. That identifier
              // cannot distinguish scheme, port, or reverse-proxy path, so never guess
              // which deployment owns it. Keep the encrypted row quarantined and require
              // a fresh login/full sync into the canonical account namespace.
              Self.accountID(server: server, email: email) == accountID else {
            // A stale/corrupt marker must not trap every future launch on the unlock screen.
            try requireRestoreLease(generation: restoreGeneration)
            await keychain.deleteSecret(account: AppShared.KeychainAccount.activeAccountID)
            await keychain.deleteSecret(account: AppShared.KeychainAccount.activeSessionID)
            try requireRestoreLease(generation: restoreGeneration)
            return nil
        }

        // A cold-restored app is a new session incarnation. Rotate the shared nonce so
        // any still-resident extension must authenticate again before returning secrets.
        do {
            try await keychain.setSecret(
                Data(UUID().uuidString.lowercased().utf8),
                account: AppShared.KeychainAccount.activeSessionID,
                biometryGated: false
            )
        } catch {
            await keychain.deleteSecret(account: AppShared.KeychainAccount.activeAccountID)
            await keychain.deleteSecret(account: AppShared.KeychainAccount.activeSessionID)
            return nil
        }
        try requireRestoreLease(generation: restoreGeneration)

        await api.setEnvironment(server)
        try requireRestoreLease(generation: restoreGeneration)
        let authenticationContextID = UUID()
        await api.bindAccount(accountID, contextID: authenticationContextID)
        try requireRestoreLease(generation: restoreGeneration)
        advanceSessionGeneration()
        sessionAuthenticationContextID = authenticationContextID
        session = AccountSession(
            accountID: accountID,
            email: email,
            kdfIterations: iterations,
            protectedUserKey: protectedUserKey
        )
        return server.base.absoluteString
    }

    // MARK: - Unlock

    /// Unlock with the master password using the in-memory session's protected user key
    /// (offline-capable: no network round-trip). Verifies against the stored local-auth
    /// hash when present, then decrypts the protected user key.
    public func unlockWithMasterPassword(_ password: String) async throws {
        guard !isLocking, !isTransitioningAuthentication,
              let session else { throw RepositoryError.notAuthenticated }
        let expectedGeneration = sessionGeneration
        let protectedKey: EncString
        do { protectedKey = try EncString(parsing: session.protectedUserKey) }
        catch { throw RepositoryError.crypto(error) }

        let masterKey: [UInt8]
        do {
            masterKey = try KDF.deriveMasterKey(
                password: password,
                email: session.email,
                iterations: session.kdfIterations
            )
            if let storedData = try? await keychain.getSecret(
                account: AppShared.KeychainAccount.localAuthHash(accountID: session.accountID)
            ) {
                try requireCurrentSession(
                    accountID: session.accountID,
                    generation: expectedGeneration
                )
                let candidate = try KDF.masterPasswordHash(
                    masterKey: masterKey,
                    password: password,
                    purpose: .localAuthorization
                )
                guard let stored = String(data: storedData, encoding: .utf8),
                      Self.constantTimeEqual(stored, candidate) else {
                    throw RepositoryError.authenticationFailed
                }
            }
        } catch let error as RepositoryError {
            throw error
        } catch {
            throw RepositoryError.authenticationFailed
        }

        let userKey: SymmetricCryptoKey
        do {
            userKey = try Self.decryptUserKey(masterKey: masterKey, protectedKey: protectedKey)
        } catch {
            throw RepositoryError.authenticationFailed
        }
        try requireCurrentSession(
            accountID: session.accountID,
            generation: expectedGeneration
        )
        await keyVault.unlock(userKey: userKey)
        try requireCurrentSession(
            accountID: session.accountID,
            generation: expectedGeneration
        )
        await encryptor.setUserKey(userKey)
        try requireCurrentSession(
            accountID: session.accountID,
            generation: expectedGeneration
        )
    }

    /// Unlock via biometrics: recover the SE-wrapped user key and hand it to the `KeyVault`
    /// (and the write-path encryptor).
    public func unlockWithBiometrics(reason: String = "Unlock Tessera") async throws {
        guard !isLocking, !isTransitioningAuthentication,
              let session else { throw RepositoryError.notAuthenticated }
        let expectedGeneration = sessionGeneration
        let binding: Data?
        do {
            binding = try await keychain.getSecret(
                account: AppShared.KeychainAccount.biometricAccountID
            )
        } catch {
            throw RepositoryError.authenticationFailed
        }
        guard let binding,
              String(data: binding, encoding: .utf8) == session.accountID else {
            throw RepositoryError.authenticationFailed
        }
        try requireCurrentSession(
            accountID: session.accountID,
            generation: expectedGeneration
        )
        let userKey: SymmetricCryptoKey
        do { userKey = try await keychain.unlockWithBiometrics(reason: reason) }
        catch { throw RepositoryError.authenticationFailed }
        try requireCurrentSession(
            accountID: session.accountID,
            generation: expectedGeneration
        )
        await keyVault.unlock(userKey: userKey)
        try requireCurrentSession(
            accountID: session.accountID,
            generation: expectedGeneration
        )
        await encryptor.setUserKey(userKey)
        try requireCurrentSession(
            accountID: session.accountID,
            generation: expectedGeneration
        )
    }

    // MARK: - Refresh / lock / logout

    /// Refresh the access token using the persisted refresh token. On success the new
    /// bearer token is set on the API client.
    @discardableResult
    public func refresh() async throws -> Bool {
        try await sessionOperationCoordinator.withLock {
            try await self.performRefresh()
        }
    }

    private func performRefresh() async throws -> Bool {
        guard !isLocking, !isTransitioningAuthentication else {
            throw RepositoryError.notAuthenticated
        }
        guard let session else { throw RepositoryError.notAuthenticated }
        let expectedSessionGeneration = sessionGeneration
        let account: AccountRow?
        do { account = try await store.account(id: session.accountID) }
        catch { throw RepositoryError.store(error) }
        try requireCurrentSession(accountID: session.accountID,
                                  generation: expectedSessionGeneration)
        guard let serverURL = account?.serverURL,
              let server = ServerEnvironment(string: serverURL) else {
            throw RepositoryError.notAuthenticated
        }

        let refreshData: Data?
        do {
            refreshData = try await keychain.getSecret(
                account: AppShared.KeychainAccount.refreshToken(accountID: session.accountID)
            )
        }
        catch { throw RepositoryError.authenticationFailed }
        try requireCurrentSession(accountID: session.accountID,
                                  generation: expectedSessionGeneration)
        guard let refreshData, let refreshToken = String(data: refreshData, encoding: .utf8) else {
            throw RepositoryError.notAuthenticated
        }

        let tokenResponse: TokenResponse
        do {
            tokenResponse = try await api.refresh(
                refreshToken: refreshToken,
                server: server,
                accountID: session.accountID
            )
        }
        catch { throw RepositoryError.network(error) }
        try requireCurrentSession(accountID: session.accountID,
                                  generation: expectedSessionGeneration)
        if let newRefresh = tokenResponse.refreshToken {
            do {
                try await keychain.setSecret(
                    Data(newRefresh.utf8),
                    account: AppShared.KeychainAccount.refreshToken(
                        accountID: session.accountID
                    ),
                    biometryGated: false
                )
            } catch {
                throw RepositoryError.authenticationFailed
            }
            try requireCurrentSession(accountID: session.accountID,
                                      generation: expectedSessionGeneration)
        }
        return true
    }

    /// Lock the vault: zero the in-memory key material (both the `KeyVault` and the
    /// write-path encryptor). The session + persisted tokens remain so the user can
    /// re-unlock without a full login.
    public func lock() async {
        await sessionOperationCoordinator.withLock {
            await self.performLock()
        }
    }

    private func performLock() async {
        isLocking = true
        defer { isLocking = false }
        // Revoke decrypt/encrypt operations and biometric prompts that suspended under
        // the prior unlocked incarnation before clearing either key holder.
        currentLoginAttemptID = nil
        pending = nil
        advanceSessionGeneration()
        // Rotate before clearing keys. New extension requests can still biometrically
        // unlock this account, while an already-unlocked extension loses its old lease.
        if session != nil {
            do {
                try await keychain.setSecret(
                    Data(UUID().uuidString.lowercased().utf8),
                    account: AppShared.KeychainAccount.activeSessionID,
                    biometryGated: false
                )
            } catch {
                await keychain.deleteSecret(account: AppShared.KeychainAccount.activeSessionID)
            }
        } else {
            await keychain.deleteSecret(account: AppShared.KeychainAccount.activeSessionID)
        }
        await keyVault.lock()
        await encryptor.clear()
    }

    /// Whether the vault is currently unlocked.
    public func isUnlocked() async -> Bool {
        guard !isLocking, !isTransitioningAuthentication else { return false }
        return await keyVault.isUnlocked
    }

    public func hasSession() -> Bool {
        !isTransitioningAuthentication && session != nil
    }

    /// Enable/disable biometric material for the current session without requiring a new
    /// login. Enabling is permitted only while the user key is already unlocked.
    public func setBiometricUnlockEnabled(_ enabled: Bool) async throws {
        biometricPolicyGeneration &+= 1
        let policyGeneration = biometricPolicyGeneration
        try await biometricPolicyCoordinator.withLock {
            try await self.performBiometricPolicyChange(
                enabled,
                policyGeneration: policyGeneration
            )
        }
    }

    private func performBiometricPolicyChange(
        _ enabled: Bool,
        policyGeneration: UInt64
    ) async throws {
        guard biometricPolicyGeneration == policyGeneration else { return }
        if !enabled {
            await keychain.deleteSecret(
                account: AppShared.KeychainAccount.biometricAccountID
            )
            guard biometricPolicyGeneration == policyGeneration else { return }
            await keychain.disableBiometricUnlock()
            return
        }
        guard !isTransitioningAuthentication,
              let session else { throw RepositoryError.notAuthenticated }
        let generation = sessionGeneration

        let userKey: SymmetricCryptoKey
        do { userKey = try await keyVault.userKeyForBiometricEnrollment() }
        catch { throw RepositoryError.locked }
        try requireCurrentSession(accountID: session.accountID, generation: generation)
        do {
            try await keychain.enableBiometricUnlock(userKey: userKey)
            try requireCurrentSession(accountID: session.accountID, generation: generation)
            try await keychain.setSecret(
                Data(session.accountID.utf8),
                account: AppShared.KeychainAccount.biometricAccountID,
                biometryGated: false
            )
            try requireCurrentSession(accountID: session.accountID, generation: generation)
        } catch let error as RepositoryError {
            if biometricPolicyGeneration == policyGeneration,
               sessionGeneration == generation,
               self.session?.accountID == session.accountID {
                await keychain.disableBiometricUnlock()
                await keychain.deleteSecret(
                    account: AppShared.KeychainAccount.biometricAccountID
                )
            }
            throw error
        } catch {
            if biometricPolicyGeneration == policyGeneration,
               sessionGeneration == generation,
               self.session?.accountID == session.accountID {
                await keychain.disableBiometricUnlock()
                await keychain.deleteSecret(
                    account: AppShared.KeychainAccount.biometricAccountID
                )
            }
            throw RepositoryError.authenticationFailed
        }
    }

    /// Current session lease for repositories that share this authentication context.
    public func currentSessionLease() -> AccountSessionLease? {
        guard !isLocking, !isTransitioningAuthentication, let session else { return nil }
        return AccountSessionLease(
            accountID: session.accountID,
            generation: sessionGeneration
        )
    }

    /// Full logout: lock, clear the session, drop the bearer token, and delete persisted
    /// secrets + biometric unlock.
    public func logout(reservedIntent: UInt64? = nil) async {
        let logoutIntent: UInt64
        if let reservedIntent {
            guard authenticationIntentGeneration == reservedIntent else { return }
            logoutIntent = reservedIntent
        } else {
            authenticationIntentGeneration &+= 1
            biometricPolicyGeneration &+= 1
            logoutIntent = authenticationIntentGeneration
        }
        isTransitioningAuthentication = true
        let cleanupLease: LogoutCleanupLease?
        if let accountID = session?.accountID ?? completingAccountID {
            let authenticationContextID = sessionAuthenticationContextID
                ?? completingAuthenticationContextID
            cleanupLease = LogoutCleanupLease(
                id: UUID(),
                accountID: accountID,
                authenticationContextID: authenticationContextID
            )
            pendingLogoutCleanup = cleanupLease
        } else {
            // `session` is cleared before the first suspension. A later logout therefore
            // inherits this lease instead of stealing the intent and losing the only copy
            // of the account/context that still needs cleanup.
            cleanupLease = pendingLogoutCleanup
        }
        // Revoke login/session ownership before the first suspension. Any in-flight login
        // commit or refresh observes this marker and cannot republish state after logout.
        session = nil
        sessionAuthenticationContextID = nil
        pending = nil
        currentLoginAttemptID = nil
        currentLoginIntentGeneration = logoutIntent
        activeTwoFactorSubmissionID = nil
        advanceSessionGeneration()
        // Login commit and logout cleanup both mutate the same Keychain/API account state.
        // Serializing them prevents a stale same-account delete from landing after a newer
        // login has written its refresh/local-auth secrets.
        await loginCommitCoordinator.withLock {
            await self.performLogoutCleanup(cleanupLease, intent: logoutIntent)
        }
    }

    // MARK: - Helpers

    private func performLogoutCleanup(
        _ cleanupLease: LogoutCleanupLease?,
        intent logoutIntent: UInt64
    ) async {
        guard authenticationIntentGeneration == logoutIntent else { return }
        // Cross-process revocation is the logout linearization point. Withdraw the
        // extension nonce/account before slower in-process/API cleanup awaits.
        await keychain.deleteSecret(account: AppShared.KeychainAccount.activeSessionID)
        guard authenticationIntentGeneration == logoutIntent else { return }
        await keychain.deleteSecret(account: AppShared.KeychainAccount.activeAccountID)
        guard authenticationIntentGeneration == logoutIntent else { return }
        await keyVault.lock()
        guard authenticationIntentGeneration == logoutIntent else { return }
        await encryptor.clear()
        guard authenticationIntentGeneration == logoutIntent else { return }
        if let accountID = cleanupLease?.accountID,
           let authenticationContextID = cleanupLease?.authenticationContextID {
            await api.clearAccountContext(
                accountID: accountID,
                contextID: authenticationContextID
            )
            guard authenticationIntentGeneration == logoutIntent else { return }
        }
        if let accountID = cleanupLease?.accountID {
            await keychain.deleteSecret(
                account: AppShared.KeychainAccount.refreshToken(accountID: accountID)
            )
            guard authenticationIntentGeneration == logoutIntent else { return }
            await keychain.deleteSecret(
                account: AppShared.KeychainAccount.localAuthHash(accountID: accountID)
            )
            guard authenticationIntentGeneration == logoutIntent else { return }
        }
        await keychain.deleteSecret(account: AppShared.KeychainAccount.legacyRefreshToken)
        guard authenticationIntentGeneration == logoutIntent else { return }
        await keychain.deleteSecret(account: AppShared.KeychainAccount.legacyLocalAuthHash)
        guard authenticationIntentGeneration == logoutIntent else { return }
        await keychain.deleteSecret(account: AppShared.KeychainAccount.biometricAccountID)
        guard authenticationIntentGeneration == logoutIntent else { return }
        await keychain.disableBiometricUnlock()
        guard authenticationIntentGeneration == logoutIntent else { return }
        if pendingLogoutCleanup?.id == cleanupLease?.id {
            pendingLogoutCleanup = nil
        }
        isTransitioningAuthentication = false
    }

    /// A terminal failure from the initial password grant is no longer an authentication
    /// transition. Only the still-current attempt may reset these flags: an older request
    /// that resumes after being superseded must leave the newer intent untouched.
    private func finishLoginFailureIfCurrent(_ attemptID: UUID) {
        guard isCurrentLoginAttempt(attemptID) else { return }
        pending = nil
        currentLoginAttemptID = nil
        activeTwoFactorSubmissionID = nil
        isTransitioningAuthentication = false
    }

    /// Undo durable/in-memory state written by a token response whose local commit failed.
    /// This runs while the login-commit coordinator is held, so a newer attempt may perform
    /// its network grant but cannot publish its session until this rollback has finished.
    private func rollbackFailedLoginCommitIfCurrent(_ pending: PendingLogin) async {
        guard isCurrentLoginAttempt(pending.attemptID) else { return }
        let accountID = Self.accountID(server: pending.server, email: pending.email)

        await keychain.deleteSecret(account: AppShared.KeychainAccount.activeAccountID)
        guard isCurrentLoginAttempt(pending.attemptID) else { return }
        await keychain.deleteSecret(account: AppShared.KeychainAccount.activeSessionID)
        guard isCurrentLoginAttempt(pending.attemptID) else { return }
        await api.clearAccountContext(
            accountID: accountID,
            contextID: pending.attemptID
        )
        guard isCurrentLoginAttempt(pending.attemptID) else { return }
        await keychain.deleteSecret(
            account: AppShared.KeychainAccount.refreshToken(accountID: accountID)
        )
        guard isCurrentLoginAttempt(pending.attemptID) else { return }
        await keychain.deleteSecret(
            account: AppShared.KeychainAccount.localAuthHash(accountID: accountID)
        )
        guard isCurrentLoginAttempt(pending.attemptID) else { return }
        await keyVault.lock()
        guard isCurrentLoginAttempt(pending.attemptID) else { return }
        await encryptor.clear()
    }

    private func isCurrentLoginAttempt(_ attemptID: UUID) -> Bool {
        currentLoginAttemptID == attemptID
            && currentLoginIntentGeneration == authenticationIntentGeneration
    }

    /// A stable per-account id derived from the canonical full deployment base + normalized
    /// email. Scheme, non-default port, and reverse-proxy path are identity-bearing so two
    /// Vaultwarden instances sharing a host cannot collide in the local cache.
    static func accountID(server: ServerEnvironment, email: String) -> String {
        let normalizedEmail = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return "\(canonicalServerBase(server.base))|\(normalizedEmail)"
    }

    private func requireCurrentLoginAttempt(_ attemptID: UUID) throws {
        guard isCurrentLoginAttempt(attemptID) else {
            throw RepositoryError.underlying(
                kind: .network,
                description: "Login attempt was superseded"
            )
        }
    }

    private func requireCurrentSession(accountID: String, generation: UInt64) throws {
        guard session?.accountID == accountID,
              sessionGeneration == generation else {
            throw RepositoryError.underlying(
                kind: .network,
                description: "Account session changed"
            )
        }
    }

    private func requireRestoreLease(generation: UInt64) throws {
        guard sessionGeneration == generation,
              currentLoginAttemptID == nil,
              !isCompletingLogin,
              !isLocking,
              !isTransitioningAuthentication else {
            throw RepositoryError.underlying(
                kind: .network,
                description: "Session restoration was superseded"
            )
        }
    }

    private func advanceSessionGeneration() {
        sessionGeneration &+= 1
    }

    private static func canonicalServerBase(_ url: URL) -> String {
        guard var components = URLComponents(url: url.standardized,
                                             resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              let host = components.host?.lowercased() else {
            return url.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        }

        components.scheme = scheme
        components.host = host
        components.user = nil
        components.password = nil
        components.query = nil
        components.fragment = nil

        // Explicit default ports and an omitted port identify the same URL origin.
        if (scheme == "https" && components.port == 443)
            || (scheme == "http" && components.port == 80) {
            components.port = nil
        }

        var path = components.percentEncodedPath
        while path.count > 1 && path.hasSuffix("/") { path.removeLast() }
        components.percentEncodedPath = path == "/" ? "" : path

        return components.string ?? url.absoluteString
    }

    /// Re-derive the raw 64-byte `UserKey` from the master password: PBKDF2 master key →
    /// HKDF-stretch → decrypt the type-2 protected user key (HMAC verified inside
    /// `SymmetricCrypto.decrypt`). This mirrors `KeyVault.unlock(password:…)` but returns
    /// the key so the repository can also SE-wrap it for biometric unlock.
    static func decryptUserKey(password: String, email: String, iterations: Int,
                               protectedKey: EncString) throws -> SymmetricCryptoKey {
        let masterKey = try KDF.deriveMasterKey(password: password, email: email, iterations: iterations)
        return try decryptUserKey(masterKey: masterKey, protectedKey: protectedKey)
    }

    private static func decryptUserKey(masterKey: [UInt8],
                                       protectedKey: EncString) throws -> SymmetricCryptoKey {
        let stretched = KeyStretch.stretchMasterKey(masterKey)
        let raw = try SymmetricCrypto.decrypt(protectedKey, using: stretched)
        return try SymmetricCryptoKey(combined: raw)
    }

    private static func constantTimeEqual(_ lhs: String, _ rhs: String) -> Bool {
        let left = Array(lhs.utf8)
        let right = Array(rhs.utf8)
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for index in left.indices { difference |= left[index] ^ right[index] }
        return difference == 0
    }
}

/// Small non-blocking mutex used for auth operations that must not overlap across actor
/// reentrancy (refresh-token rotation and lock completion).
private actor AuthOperationCoordinator {
    private var isHeld = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func withLock<T: Sendable>(
        _ operation: @Sendable () async throws -> T
    ) async rethrows -> T {
        await acquire()
        defer { release() }
        return try await operation()
    }

    private func acquire() async {
        guard isHeld else {
            isHeld = true
            return
        }
        await withCheckedContinuation { waiters.append($0) }
    }

    private func release() {
        if waiters.isEmpty {
            isHeld = false
        } else {
            waiters.removeFirst().resume()
        }
    }
}
