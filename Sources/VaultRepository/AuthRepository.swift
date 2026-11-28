import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import KeychainBridge
import Networking
import AppShared

#if os(macOS)
public enum SessionTimeoutResult: Sendable, Equatable {
    case superseded, locked, loggedOut, logoutFailedLocked
}
#endif

/// App-facing authentication and unlock orchestration.
///
/// Owns the login → KDF → token → unlock pipeline, the 2FA round-trip, and the
/// persistence of the refresh token + offline local-auth hash. PBKDF2-only: a
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
    private let usesLocalSessionStore: Bool
    private let localBiometrics: (any LocalBiometricKeyWrapping)?
    private let autoFillAccess: AutoFillAccessGate?
    private let onUnlockInvalidated: @Sendable () async -> Void

    /// The active session after a successful login (account id, email, KDF iters,
    /// protected user key). `nil` until login succeeds / after `logout`.
    public private(set) var session: AccountSession?
    private var needsNewLogin = false

    public func requiresNewLogin() -> Bool { needsNewLogin }

    /// Distinguishes successive incarnations of the same canonical account (ABA guard).
    private var sessionGeneration: UInt64 = 0
    /// Mirrors the unique owner installed in `AuthAPI` for the published session.
    private var sessionAuthenticationContextID: UUID?
    #if os(macOS)
    private var sessionPublishedAt: ContinuousClock.Instant?
    #endif
    private struct LocalSessionIdentity: Equatable, Sendable {
        let accountID: String
        let id: UUID

        init(_ record: LocalVaultSession) {
            accountID = record.accountID
            id = record.id
        }

        var biometricBinding: Data { Data("\(id.uuidString):\(accountID)".utf8) }
    }
    private struct LocalBiometricPrompt {
        let id: UUID
        let task: Task<SymmetricCryptoKey, Error>
    }
    private var localSessionIdentity: LocalSessionIdentity?
    private var localBiometricPrompt: LocalBiometricPrompt?
    private var localBiometricPolicyChange: UInt64?

    /// In-flight login state retained between the first `login` and a `submitTwoFactor`
    /// retry: the credentials + derived hashes so the retry doesn't re-run the KDF.
    private struct PendingLogin: Sendable {
        let attemptID: UUID
        let email: String
        let wrappingKey: SymmetricCryptoKey?
        let iterations: Int
        let serverHash: String?
        let localHash: String?
        let approvedDevice: DeviceLoginGrant?
        /// The server that produced the prelogin/KDF parameters. A 2FA retry must use
        /// this exact environment; switching servers mid-challenge is rejected.
        let server: ServerEnvironment
    }
    private var pending: PendingLogin? {
        didSet {
            deviceGrantExpiry?.cancel()
            deviceGrantExpiry = nil
            if let attempt = pending?.attemptID, let expiresAt = pending?.approvedDevice?.expiresAt {
                deviceGrantExpiry = Task { [weak self] in
                    do { try await ContinuousClock().sleep(until: expiresAt) } catch { return }
                    await self?.expirePendingDeviceGrant(attempt)
                }
            }
        }
    }
    private var deviceGrantExpiry: Task<Void, Never>?
    private var currentLoginAttemptID: UUID?
    private var currentLoginIntentGeneration: UInt64 = 0
    private var authenticationIntentGeneration: UInt64 = 0
    private var activeTwoFactorSubmissionID: UUID?
    private var offeredWebAuthn: WebAuthnSecondFactorChallenge?
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
                encryptor: VaultEncrypting, usesLocalSessionStore: Bool = false,
                localBiometrics: (any LocalBiometricKeyWrapping)? = nil,
                autoFillAccess: AutoFillAccessGate? = nil,
                onUnlockInvalidated: @escaping @Sendable () async -> Void = {}) {
        self.autoFillAccess = autoFillAccess
        self.onUnlockInvalidated = onUnlockInvalidated
        self.api = api
        self.keyVault = keyVault
        self.keychain = keychain
        self.store = store
        self.encryptor = encryptor
        self.usesLocalSessionStore = usesLocalSessionStore
        self.localBiometrics = localBiometrics
    }

    // MARK: - Login

    /// Reserve ordering before UI adapters perform asynchronous policy/identity work.
    public func reserveAuthenticationIntent() async -> UInt64 {
        autoFillAccess?.deactivate()
        authenticationIntentGeneration &+= 1
        biometricPolicyGeneration &+= 1
        cancelLocalBiometricPrompt()
        isTransitioningAuthentication = true
        currentLoginAttemptID = nil
        activeTwoFactorSubmissionID = nil
        let generation = authenticationIntentGeneration
        guard !usesLocalSessionStore else { return generation }
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
    /// `prelogin` → **reject kdf != 0 (PBKDF2-only)** → derive master key → server-auth
    /// hash → `token`. On success the protected user key is decrypted into the `KeyVault`,
    /// the refresh token + offline local-auth hash are persisted, and biometric unlock is
    /// enabled when `enableBiometrics` is set. A 2FA challenge returns
    /// `.twoFactorRequired`; the caller answers via `submitTwoFactor`.
    public func login(email: String, password: String, server: ServerEnvironment,
                      enableBiometrics: Bool = false,
                      reservedIntent: UInt64? = nil) async throws -> LoginResult {
        try await startLogin(email: email, password: password, server: server, approvedDevice: nil,
                             enableBiometrics: enableBiometrics, reservedIntent: reservedIntent)
    }

    package func acceptDeviceLogin(email: String, server: ServerEnvironment, grant: DeviceLoginGrant) async throws -> LoginResult {
        // A device grant may not replace a session or an in-progress password login.
        guard session == nil, !isTransitioningAuthentication, currentLoginAttemptID == nil else {
            throw RepositoryError.notAuthenticated
        }
        return try await startLogin(email: email, password: nil, server: server, approvedDevice: grant,
                                    enableBiometrics: false, reservedIntent: nil)
    }

    private func startLogin(email: String, password: String?, server: ServerEnvironment,
                            approvedDevice: DeviceLoginGrant?, enableBiometrics: Bool,
                            reservedIntent: UInt64?) async throws -> LoginResult {
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
        autoFillAccess?.deactivate()
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
            offeredWebAuthn = nil
            session = nil
            sessionAuthenticationContextID = nil
            advanceSessionGeneration()
            // Withdraw the published account at the start of the transition. A failed or
            // suspended login must not leave the AutoFill extension able to vend the previous
            // account while the app has already abandoned that session.
            if !usesLocalSessionStore {
                await keychain.deleteSecret(account: AppShared.KeychainAccount.activeAccountID)
                try requireCurrentLoginAttempt(attemptID)
                await keychain.deleteSecret(account: AppShared.KeychainAccount.activeSessionID)
                try requireCurrentLoginAttempt(attemptID)
            }
            if usesLocalSessionStore {
                try await loginCommitCoordinator.withLock {
                    try await self.prepareLoginAuthorization(server: server, attemptID: attemptID)
                }
            } else {
                try await prepareLoginAuthorization(server: server, attemptID: attemptID)
            }
            try requireCurrentLoginAttempt(attemptID)

            let prelogin: PreloginResponse
            do { prelogin = try await api.prelogin(email: normalizedEmail, server: server) }
            catch { throw RepositoryError.network(error) }
            try requireCurrentLoginAttempt(attemptID)

            // PBKDF2-only guard: kdf == 0 is PBKDF2; anything else (1 = Argon2id) is rejected
            // with a clear error BEFORE any derivation.
            guard prelogin.kdf == 0 else { throw RepositoryError.unsupportedKDF(prelogin.kdf) }

            let pending: PendingLogin
            do {
                if let password {
                    var masterKey = try KDF.deriveMasterKey(password: password, email: normalizedEmail,
                                                           iterations: prelogin.kdfIterations)
                    defer { masterKey.withUnsafeMutableBytes(SecureBytes.erase) }
                    pending = PendingLogin(
                        attemptID: attemptID, email: normalizedEmail, wrappingKey: KeyStretch.stretchMasterKey(masterKey),
                        iterations: prelogin.kdfIterations,
                        serverHash: try KDF.masterPasswordHash(masterKey: masterKey, password: password, purpose: .serverAuthorization),
                        localHash: try KDF.masterPasswordHash(masterKey: masterKey, password: password, purpose: .localAuthorization),
                        approvedDevice: nil, server: server
                    )
                } else if let approvedDevice {
                    try KDF.validatePBKDF2Iterations(prelogin.kdfIterations)
                    pending = PendingLogin(attemptID: attemptID, email: normalizedEmail, wrappingKey: nil,
                                           iterations: prelogin.kdfIterations, serverHash: nil, localHash: nil,
                                           approvedDevice: approvedDevice, server: server)
                } else {
                    throw RepositoryError.authenticationFailed
                }
            } catch {
                throw RepositoryError.crypto(error)
            }
            let accountID = Self.accountID(server: server, email: normalizedEmail)
            let rememberedToken: String?
            if usesLocalSessionStore {
                rememberedToken = try? await store.localVaultRememberedDevice(accountID: accountID)
            } else {
                let saved = try? await keychain.getSecret(account: AppShared.KeychainAccount.rememberedDevice(accountID: accountID))
                rememberedToken = saved.flatMap { String(data: $0, encoding: .utf8) }
            }
            try requireCurrentLoginAttempt(attemptID)
            let remembered = rememberedToken.map { TwoFactorPayload(provider: .remember, token: $0, remember: true) }
            return try await requestToken(pending: pending, twoFactor: remembered,
                                          enableBiometrics: enableBiometrics)
        } catch {
            finishLoginFailureIfCurrent(attemptID)
            throw error
        }
    }

    private func prepareLoginAuthorization(server: ServerEnvironment, attemptID: UUID) async throws {
        if usesLocalSessionStore { try requireCurrentLoginAttempt(attemptID) }
        await api.setEnvironment(server)
        try requireCurrentLoginAttempt(attemptID)
        await keyVault.lock()
        try requireCurrentLoginAttempt(attemptID)
        await encryptor.clear()
        try requireCurrentLoginAttempt(attemptID)
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
        let submittedToken: String
        if provider == .webAuthn {
            guard let challenge = offeredWebAuthn else { throw RepositoryError.authenticationFailed }
            submittedToken = try challenge.validate(token: token, environment: server)
            offeredWebAuthn = nil
        } else if provider == .recoveryCode {
            guard pending.approvedDevice == nil, !remember else { throw RepositoryError.authenticationFailed }
            submittedToken = token.filter { $0 != " " }.lowercased()
            guard (16...128).contains(submittedToken.utf8.count), submittedToken.utf8.allSatisfy({
                (97...122).contains($0) || (48...57).contains($0)
            }) else { throw RepositoryError.authenticationFailed }
        } else {
            submittedToken = token
        }
        let payload = TwoFactorPayload(provider: provider, token: submittedToken, remember: remember)
        return try await requestToken(pending: pending, twoFactor: payload,
                                      enableBiometrics: enableBiometrics)
    }

    public struct SecurityKeyAttempt: Sendable {
        fileprivate let id: UUID
        public let challenge: WebAuthnSecondFactorChallenge
    }

    public func securityKeyAttempt(server: ServerEnvironment) throws -> SecurityKeyAttempt {
        guard let pending, pending.server == server, let challenge = offeredWebAuthn else {
            throw RepositoryError.authenticationFailed
        }
        try requireCurrentLoginAttempt(pending.attemptID)
        return SecurityKeyAttempt(id: pending.attemptID, challenge: challenge)
    }

    public func submitSecurityKey(_ attempt: SecurityKeyAttempt, token: String, remember: Bool,
                                  server: ServerEnvironment, enableBiometrics: Bool) async throws -> LoginResult {
        try requireCurrentLoginAttempt(attempt.id)
        guard offeredWebAuthn == attempt.challenge else { throw RepositoryError.authenticationFailed }
        return try await submitTwoFactor(provider: .webAuthn, token: token, remember: remember,
                                         server: server, enableBiometrics: enableBiometrics)
    }

    /// Shared token-grant + post-success unlock/persist path.
    private func requestToken(pending: PendingLogin, twoFactor: TwoFactorPayload?,
                              enableBiometrics: Bool) async throws -> LoginResult {
        let result: TokenResult
        do {
            if let approvedDevice = pending.approvedDevice {
                try approvedDevice.checkExpiry()
                result = try await api.deviceLoginToken(email: pending.email, accessCode: approvedDevice.accessCode,
                    requestID: approvedDevice.requestID, twoFactor: twoFactor, server: pending.server)
            } else if let serverHash = pending.serverHash {
                result = try await api.token(email: pending.email, passwordHash: serverHash,
                                             twoFactor: twoFactor, server: pending.server)
            } else { throw RepositoryError.authenticationFailed }
        } catch NetworkingError.unauthorized {
            throw RepositoryError.authenticationFailed
        } catch NetworkingError.http(status: 400, body: _) {
            throw RepositoryError.authenticationFailed
        } catch {
            throw RepositoryError.network(error)
        }
        try requireCurrentLoginAttempt(pending.attemptID)

        switch result {
        case .twoFactorRequired(let providers):
            if twoFactor?.provider == .remember {
                let accountID = Self.accountID(server: pending.server, email: pending.email)
                if usesLocalSessionStore {
                    try await loginCommitCoordinator.withLock {
                        try await self.removeRejectedLocalRememberedDevice(accountID: accountID, attemptID: pending.attemptID)
                    }
                } else {
                    await keychain.deleteSecret(account: AppShared.KeychainAccount.rememberedDevice(accountID: accountID))
                }
                try requireCurrentLoginAttempt(pending.attemptID)
            }
            // Retain the derived hashes so the retry skips the KDF.
            self.pending = pending
            offeredWebAuthn = providers.webAuthnChallenge.flatMap { challenge in
                (try? challenge.validate(environment: pending.server)) != nil ? challenge : nil
            }
            if providers.providers.count > 1 && providers.providers.contains(.email) {
                try? await sendEmail(for: pending)
                try requireCurrentLoginAttempt(pending.attemptID)
            }
            return .twoFactorRequired(providers.providers)

        case .success(let tokenResponse):
            try await loginCommitCoordinator.withLock {
                do {
                    if twoFactor?.provider == .recoveryCode {
                        await self.forgetRecoveredDevice(pending)
                    }
                    try await self.completeLogin(
                        tokenResponse,
                        pending: pending,
                        enableBiometrics: enableBiometrics,
                        rememberDevice: twoFactor?.remember == true
                    )
                } catch {
                    await self.rollbackFailedLoginCommitIfCurrent(pending)
                    throw error
                }
            }
            try requireCurrentLoginAttempt(pending.attemptID)
            self.pending = nil
            offeredWebAuthn = nil
            currentLoginAttemptID = nil
            isTransitioningAuthentication = false
            if let accountID = session?.accountID {
                await enableAutoFillAccess(accountID: accountID, generation: sessionGeneration)
                guard sessionAuthenticationContextID == pending.attemptID else { throw RepositoryError.locked }
            }
            return .success
        }
    }

    private func forgetRecoveredDevice(_ login: PendingLogin) async {
        guard isCurrentLoginAttempt(login.attemptID) else { return }
        let accountID = Self.accountID(server: login.server, email: login.email)
        if usesLocalSessionStore {
            try? await store.removeLocalVaultRememberedDevice(accountID: accountID)
        } else {
            await keychain.deleteSecret(account: AppShared.KeychainAccount.rememberedDevice(accountID: accountID))
        }
    }

    private func removeRejectedLocalRememberedDevice(accountID: String, attemptID: UUID) async throws {
        try requireCurrentLoginAttempt(attemptID)
        try? await store.removeLocalVaultRememberedDevice(accountID: accountID)
    }

    public func sendTwoFactorEmail(server: ServerEnvironment) async throws {
        guard let pending else { throw RepositoryError.notAuthenticated }
        try requireCurrentLoginAttempt(pending.attemptID)
        guard pending.server == server else { throw RepositoryError.notAuthenticated }
        do { try await sendEmail(for: pending) }
        catch { throw RepositoryError.network(error) }
        try requireCurrentLoginAttempt(pending.attemptID)
    }

    private func sendEmail(for pending: PendingLogin) async throws {
        if let device = pending.approvedDevice {
            try device.checkExpiry()
            try await api.sendDeviceLoginEmailCode(email: pending.email, accessCode: device.accessCode,
                                                  requestID: device.requestID, server: pending.server)
        } else if let serverHash = pending.serverHash {
            try await api.sendEmailLoginCode(email: pending.email, masterPasswordHash: serverHash, server: pending.server)
        } else { throw RepositoryError.authenticationFailed }
    }

    public func requestPasswordHint(email: String, server: ServerEnvironment) async throws {
        do { try await api.requestPasswordHint(email: email, server: server) }
        catch { throw RepositoryError.network(error) }
    }

    public func cancelTwoFactor(email: String, server: ServerEnvironment) {
        guard let pending, pending.email == email, pending.server == server,
              activeTwoFactorSubmissionID == nil, !isCompletingLogin else { return }
        finishLoginFailureIfCurrent(pending.attemptID)
    }

    /// Decrypt the protected user key, durably persist the account, then publish the new
    /// in-memory session. Persisting first avoids leaving a usable bearer/user key behind if
    /// the encrypted store rejects the account row.
    private func completeLogin(_ tokenResponse: TokenResponse, pending: PendingLogin,
                               enableBiometrics: Bool, rememberDevice: Bool) async throws {
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
            if let device = pending.approvedDevice {
                try device.checkExpiry()
                guard tokenResponse.kdf == 0, tokenResponse.kdfIterations == pending.iterations,
                      let privateKey = tokenResponse.privateKey else { throw RepositoryError.authenticationFailed }
                var verified = try SymmetricCrypto.decrypt(privateKey, using: device.userKey)
                defer { verified.withUnsafeMutableBytes(SecureBytes.erase) }
                guard !verified.isEmpty else { throw RepositoryError.authenticationFailed }
                userKey = device.userKey
            } else if let wrappingKey = pending.wrappingKey {
                userKey = try Self.unwrapUserKey(protectedKey, using: wrappingKey)
            } else { throw RepositoryError.authenticationFailed }
        } catch { throw RepositoryError.authenticationFailed }
        let accountID = Self.accountID(server: pending.server, email: pending.email)
        completingAccountID = accountID
        completingAuthenticationContextID = pending.attemptID
        let accountRow = AccountRow(
            id: accountID, email: pending.email, serverURL: pending.server.base.absoluteString,
            kdfType: 0, kdfIters: pending.iterations,
            encUserKey: protectedKey.stringValue,
            encPrivateKey: tokenResponse.privateKey?.stringValue
        )
        let rememberedToken = rememberDevice && tokenResponse.twoFactorToken?.isEmpty == false
            ? tokenResponse.twoFactorToken : nil
        if let previous = try await store.account(id: accountID),
           let previousKey = previous.encUserKey,
           Self.hasChangedUnlock(previousKey: previousKey, currentKey: protectedKey),
           !Self.sameUserKey(previousKey: previousKey, current: userKey, wrappingKey: pending.wrappingKey) {
            // A fresh sign-in must not replay mutations encrypted under the prior key.
            // A rewrap cannot always be distinguished here; keep ambiguous edits for review.
            try requireCurrentLoginAttempt(pending.attemptID)
            try await store.parkOutboxForChangedAccountKey(accountID: accountID)
            try requireCurrentLoginAttempt(pending.attemptID)
        }
        if usesLocalSessionStore {
            try await installLoginAuthorization(userKey: userKey, tokenResponse: tokenResponse,
                                                pending: pending, accountID: accountID)
            try Task.checkCancellation()
            let localRecord = LocalVaultSession(accountID: accountID, id: pending.attemptID,
                                                localAuthHash: pending.localHash ?? "",
                                                refreshToken: tokenResponse.refreshToken)
            do {
                try await store.installLocalVaultSession(localRecord, rememberedDevice: rememberedToken,
                                                         account: accountRow)
            } catch {
                throw RepositoryError.store(error)
            }
            localSessionIdentity = LocalSessionIdentity(localRecord)
            if !isCurrentLoginAttempt(pending.attemptID) {
                if (try? await store.removeLocalVaultSession(accountID: accountID, sessionID: localRecord.id)) == true {
                    localSessionIdentity = nil
                }
                await api.clearAccountContext(accountID: accountID, contextID: pending.attemptID)
                try requireCurrentLoginAttempt(pending.attemptID)
            }
            publishLogin(pending, accountID: accountID, protectedKey: protectedKey)
            return
        }
        // Withdraw the old account before changing any account-scoped persistence. If this
        // login is interrupted, no marker can pair one account's server with another token.
        await keychain.deleteSecret(account: AppShared.KeychainAccount.activeAccountID)
        try requireCurrentLoginAttempt(pending.attemptID)
        // Persist the account row (so sync + unlock can find it).
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
            // No offline password proof exists after a device grant. An empty sentinel
            // selects authenticated key unwrapping instead of reusing an older proof.
            try await keychain.setSecret(
                Data((pending.localHash ?? "").utf8),
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

        try await installLoginAuthorization(userKey: userKey, tokenResponse: tokenResponse,
                                            pending: pending, accountID: accountID)

        if let token = rememberedToken {
            try? await keychain.setSecret(Data(token.utf8), account: AppShared.KeychainAccount.rememberedDevice(accountID: accountID),
                                          biometryGated: false)
            try requireCurrentLoginAttempt(pending.attemptID)
        }

        // Publish only after the API's server/account/bearer triple is ready. Callers that
        // observe a session can therefore never start sync against a half-bound context.
        publishLogin(pending, accountID: accountID, protectedKey: protectedKey)

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

    private func installLoginAuthorization(userKey: SymmetricCryptoKey, tokenResponse: TokenResponse,
                                           pending: PendingLogin, accountID: String) async throws {
        await keyVault.unlock(userKey: userKey)
        try requireCurrentLoginAttempt(pending.attemptID)
        await encryptor.setUserKey(userKey)
        try requireCurrentLoginAttempt(pending.attemptID)
        await api.setEnvironment(pending.server)
        try requireCurrentLoginAttempt(pending.attemptID)
        await api.bindAccount(accountID, contextID: pending.attemptID)
        try requireCurrentLoginAttempt(pending.attemptID)
        do {
            try await api.installAccessToken(tokenResponse.accessToken, expiresIn: tokenResponse.expiresIn,
                                             for: accountID, contextID: pending.attemptID)
        } catch { throw RepositoryError.network(error) }
        try requireCurrentLoginAttempt(pending.attemptID)
    }

    private func publishLogin(_ pending: PendingLogin, accountID: String, protectedKey: EncString) {
        needsNewLogin = false
        sessionAuthenticationContextID = pending.attemptID
        session = AccountSession(
            accountID: accountID,
            email: pending.email,
            serverURL: pending.server.base.absoluteString,
            kdfIterations: pending.iterations,
            protectedUserKey: protectedKey.stringValue
        )
        #if os(macOS)
        sessionPublishedAt = .now
        #endif
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
        if usesLocalSessionStore {
            return try await loginCommitCoordinator.withLock {
                try await self.restoreCurrentSession()
            }
        }
        return try await restoreCurrentSession()
    }

    private func restoreCurrentSession() async throws -> String? {
        if usesLocalSessionStore {
            try requireRestoreLease(generation: sessionGeneration)
        }
        if let existingSession = session {
            let generation = sessionGeneration
            if usesLocalSessionStore {
                _ = try await requireLocalSession(accountID: existingSession.accountID)
            }
            let account = try await store.account(id: existingSession.accountID)
            try requireCurrentSession(
                accountID: existingSession.accountID,
                generation: generation
            )
            if let serverURL = account?.serverURL {
                if usesLocalSessionStore {
                    guard let email = account?.email, let server = ServerEnvironment(string: serverURL),
                          Self.accountID(server: server, email: email) == existingSession.accountID else {
                        throw RepositoryError.underlying(kind: .store, description: "Standalone session does not match its account")
                    }
                }
                return serverURL
            }
        }

        let restoreGeneration = sessionGeneration
        try requireRestoreLease(generation: restoreGeneration)

        let accountMarker: String?
        do {
            if usesLocalSessionStore {
                let record = try await store.localVaultSession()
                localSessionIdentity = record.map(LocalSessionIdentity.init)
                accountMarker = record?.accountID
            } else {
                let marker = try await keychain.getSecret(account: AppShared.KeychainAccount.activeAccountID)
                accountMarker = marker.flatMap { String(data: $0, encoding: .utf8) }
            }
        } catch {
            throw RepositoryError.store(error)
        }
        try requireRestoreLease(generation: restoreGeneration)
        guard let accountID = accountMarker, !accountID.isEmpty else {
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
            if usesLocalSessionStore {
                throw RepositoryError.underlying(kind: .store, description: "Standalone session does not match its account")
            }
            // A stale/corrupt marker must not trap every future launch on the unlock screen.
            try requireRestoreLease(generation: restoreGeneration)
            await keychain.deleteSecret(account: AppShared.KeychainAccount.activeAccountID)
            await keychain.deleteSecret(account: AppShared.KeychainAccount.activeSessionID)
            try requireRestoreLease(generation: restoreGeneration)
            return nil
        }

        // A cold-restored app is a new session incarnation. Rotate the shared nonce so
        // any still-resident extension must authenticate again before returning secrets.
        if !usesLocalSessionStore {
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
        }

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
            serverURL: server.base.absoluteString,
            kdfIterations: iterations,
            protectedUserKey: protectedUserKey
        )
        #if os(macOS)
        sessionPublishedAt = .now
        #endif
        return server.base.absoluteString
    }

    private func enableAutoFillAccess(accountID: String, generation: UInt64) async {
        guard let autoFillAccess,
              let account = try? await keychain.getSecret(account: AppShared.KeychainAccount.activeAccountID),
              account == Data(accountID.utf8),
              let nonce = try? await keychain.getSecret(account: AppShared.KeychainAccount.activeSessionID),
              let sessionID = String(data: nonce, encoding: .utf8),
              currentSessionLease() == AccountSessionLease(accountID: accountID, generation: generation) else { return }
        autoFillAccess.activate(sessionID: sessionID)
    }

    private func requireLocalSession(accountID: String) async throws -> LocalVaultSession {
        guard let identity = localSessionIdentity, identity.accountID == accountID else {
            throw RepositoryError.notAuthenticated
        }
        let record: LocalVaultSession?
        do { record = try await store.localVaultSession() }
        catch { throw RepositoryError.store(error) }
        guard let record, LocalSessionIdentity(record) == identity, localSessionIdentity == identity else {
            throw RepositoryError.notAuthenticated
        }
        return record
    }

    // MARK: - Unlock

    /// Unlock with the master password using the in-memory session's protected user key
    /// (offline-capable: no network round-trip). Verifies against the stored local-auth
    /// hash when present, then decrypts the protected user key.
    public func unlockWithMasterPassword(_ password: String, expectedSession: AccountSessionLease? = nil) async throws {
        guard !needsNewLogin else { throw RepositoryError.reauthenticationRequired }
        guard let lease = currentSessionLease(), expectedSession.map({ $0 == lease }) != false else {
            throw RepositoryError.notAuthenticated
        }
        try await loginCommitCoordinator.withLock {
            try Task.checkCancellation()
            try await self.requireCurrentSession(accountID: lease.accountID, generation: lease.generation)
            try await self.performMasterPasswordUnlock(password, cancelIfInterrupted: expectedSession != nil)
        }
    }

    private func performMasterPasswordUnlock(_ password: String, cancelIfInterrupted: Bool) async throws {
        guard !isLocking, !isTransitioningAuthentication,
              let session else { throw RepositoryError.notAuthenticated }
        let expectedGeneration = sessionGeneration
        let protectedKey: EncString
        var masterKey: [UInt8]
        do {
            protectedKey = try EncString(parsing: session.protectedUserKey)
            masterKey = try KDF.deriveMasterKey(password: password, email: session.email, iterations: session.kdfIterations)
        } catch { throw RepositoryError.crypto(error) }
        defer { masterKey.withUnsafeMutableBytes(SecureBytes.erase) }

        do {
            let storedHash: String?
            if usesLocalSessionStore {
                storedHash = try await requireLocalSession(accountID: session.accountID).localAuthHash
            } else if let data = try? await keychain.getSecret(
                account: AppShared.KeychainAccount.localAuthHash(accountID: session.accountID)
            ) {
                guard let existingHash = String(data: data, encoding: .utf8) else {
                    throw RepositoryError.authenticationFailed
                }
                storedHash = existingHash
            } else {
                storedHash = nil
            }
            if let storedHash, !storedHash.isEmpty {
                try requireCurrentSession(
                    accountID: session.accountID,
                    generation: expectedGeneration
                )
                let candidate = try KDF.masterPasswordHash(
                    masterKey: masterKey,
                    password: password,
                    purpose: .localAuthorization
                )
                guard Self.constantTimeEqual(storedHash, candidate) else {
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
        if usesLocalSessionStore, cancelIfInterrupted {
            func checkRequest() throws {
                try Task.checkCancellation()
                try requireCurrentSession(accountID: session.accountID, generation: expectedGeneration)
            }
            try await installLocalUnlockedKeys(userKey, checkRequest: checkRequest)
        } else {
            try await installUnlockedKeys(userKey, accountID: session.accountID, generation: expectedGeneration)
        }
    }

    /// Unlock via biometrics: recover the SE-wrapped user key and hand it to the `KeyVault`
    /// (and the write-path encryptor).
    public func unlockWithBiometrics(reason: String = "Unlock Tessera") async throws {
        guard !needsNewLogin else { throw RepositoryError.reauthenticationRequired }
        if usesLocalSessionStore {
            try await unlockLocalSessionWithBiometrics(reason: reason)
            return
        }
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
        try await loginCommitCoordinator.withLock {
            try await self.installUnlockedKeys(userKey, accountID: session.accountID, generation: expectedGeneration)
        }
    }

    private func installUnlockedKeys(_ userKey: SymmetricCryptoKey, accountID: String, generation: UInt64) async throws {
        try Task.checkCancellation()
        try requireCurrentSession(accountID: accountID, generation: generation)
        await encryptor.setUserKey(userKey)
        try requireCurrentSession(accountID: accountID, generation: generation)
        await keyVault.unlock(userKey: userKey)
        try requireCurrentSession(accountID: accountID, generation: generation)
        await enableAutoFillAccess(accountID: accountID, generation: generation)
        try requireCurrentSession(accountID: accountID, generation: generation)
    }

    #if os(macOS)
    public func unlockForSSHAgentWithTouchID(reason: String, fallbackTitle: String,
                                            expectedSession: AccountSessionLease) async throws {
        guard !needsNewLogin, usesLocalSessionStore, currentSessionLease() == expectedSession else {
            throw RepositoryError.notAuthenticated
        }
        try await unlockLocalSessionWithBiometrics(reason: reason, fallbackTitle: fallbackTitle)
    }
    #endif

    private func unlockLocalSessionWithBiometrics(reason: String, fallbackTitle: String? = nil) async throws {
        try Task.checkCancellation()
        guard let identity = localSessionIdentity, let lease = currentSessionLease(),
              lease.accountID == identity.accountID, localBiometricPolicyChange == nil, localBiometricPrompt == nil else {
            throw RepositoryError.authenticationFailed
        }
        let policyGeneration = biometricPolicyGeneration
        guard let wrapper = localBiometrics, let envelope = try await localBiometricEnvelope(for: identity) else {
            if fallbackTitle != nil { throw KeychainError.unavailable }
            throw RepositoryError.authenticationFailed
        }
        try requireLocalBiometricSession(identity, lease: lease, policyGeneration: policyGeneration)
        guard localBiometricPrompt == nil, localBiometricPolicyChange == nil else {
            throw RepositoryError.authenticationFailed
        }

        let binding = identity.biometricBinding
        let prompt = LocalBiometricPrompt(id: UUID(), task: Task {
            try await wrapper.unwrap(envelope, binding: binding, reason: reason, fallbackTitle: fallbackTitle ?? "")
        })
        localBiometricPrompt = prompt
        defer {
            if localBiometricPrompt?.id == prompt.id { localBiometricPrompt = nil }
        }
        let userKey: SymmetricCryptoKey
        do {
            userKey = try await withTaskCancellationHandler {
                try await prompt.task.value
            } onCancel: {
                prompt.task.cancel()
            }
        } catch let error as KeychainError where fallbackTitle != nil {
            throw error
        } catch {
            throw RepositoryError.authenticationFailed
        }
        try await loginCommitCoordinator.withLock {
            try await self.commitLocalBiometricUnlock(userKey, envelope: envelope, identity: identity,
                                                      lease: lease, policyGeneration: policyGeneration, promptID: prompt.id)
        }
    }

    private func commitLocalBiometricUnlock(
        _ userKey: SymmetricCryptoKey, envelope: Data, identity: LocalSessionIdentity,
        lease: AccountSessionLease, policyGeneration: UInt64, promptID: UUID
    ) async throws {
        func checkRequest() throws {
            try requireLocalBiometricSession(identity, lease: lease, policyGeneration: policyGeneration)
            guard localBiometricPrompt?.id == promptID else { throw RepositoryError.authenticationFailed }
        }

        try checkRequest()
        guard try await localBiometricEnvelope(for: identity) == envelope else {
            throw RepositoryError.authenticationFailed
        }
        try await installLocalUnlockedKeys(userKey, checkRequest: checkRequest)
    }

    private func installLocalUnlockedKeys(_ userKey: SymmetricCryptoKey, checkRequest: () throws -> Void) async throws {
        try checkRequest()
        let alreadyUnlocked = await keyVault.isUnlocked
        try checkRequest()
        guard !alreadyUnlocked else { return }
        do {
            await encryptor.setUserKey(userKey)
            try checkRequest()
            await keyVault.unlock(userKey: userKey)
            try checkRequest()
        } catch {
            await keyVault.lock()
            await encryptor.clear()
            throw error
        }
    }

    private func localBiometricEnvelope(for identity: LocalSessionIdentity) async throws -> Data? {
        do { return try await store.localBiometricEnvelope(accountID: identity.accountID, sessionID: identity.id) }
        catch { throw RepositoryError.store(error) }
    }

    private func requireLocalBiometricSession(
        _ identity: LocalSessionIdentity, lease: AccountSessionLease, policyGeneration: UInt64
    ) throws {
        try Task.checkCancellation()
        guard localSessionIdentity == identity, currentSessionLease() == lease,
              biometricPolicyGeneration == policyGeneration else { throw RepositoryError.authenticationFailed }
    }

    private func cancelLocalBiometricPrompt() {
        localBiometricPrompt?.task.cancel()
        localBiometricPrompt = nil
    }

    // MARK: - Refresh / lock / logout

    /// Refresh the access token using the persisted refresh token. On success the new
    /// bearer token is set on the API client.
    @discardableResult
    public func refresh() async throws -> Bool {
        guard session != nil else { throw RepositoryError.notAuthenticated }
        guard let lease = await unlockedSessionLease() else { throw RepositoryError.locked }
        return try await sessionOperationCoordinator.withLock {
            try await self.performRefresh(expected: lease)
        }
    }

    package func ensureAccessToken(for lease: AccountSessionLease) async throws {
        try await sessionOperationCoordinator.withLock {
            try await self.prepareSyncAccess(for: lease)
        }
    }

    private func prepareSyncAccess(for lease: AccountSessionLease) async throws {
        try Task.checkCancellation()
        guard await unlockedSessionLease() == lease, let contextID = sessionAuthenticationContextID else {
            throw RepositoryError.locked
        }
        let hasUsableToken = try await api.hasUsableAccessToken(accountID: lease.accountID, contextID: contextID)
        guard currentSessionLease() == lease else { throw RepositoryError.notAuthenticated }
        if !hasUsableToken {
            _ = try await performRefresh(expected: lease)
            guard currentSessionLease() == lease else { throw RepositoryError.notAuthenticated }
        }
    }

    private func performRefresh(expected lease: AccountSessionLease) async throws -> Bool {
        guard await unlockedSessionLease() == lease, let session,
              let contextID = sessionAuthenticationContextID else { throw RepositoryError.locked }
        let expectedSessionGeneration = lease.generation
        let authenticationIntent = authenticationIntentGeneration
        let account: AccountRow?
        do { account = try await store.account(id: session.accountID) }
        catch { throw RepositoryError.store(error) }
        try requireCurrentSession(accountID: session.accountID,
                                  generation: expectedSessionGeneration)
        guard let serverURL = account?.serverURL,
              let server = ServerEnvironment(string: serverURL) else {
            throw RepositoryError.notAuthenticated
        }

        let localRecord: LocalVaultSession?
        let refreshToken: String?
        if usesLocalSessionStore {
            guard let email = account?.email, Self.accountID(server: server, email: email) == session.accountID else {
                throw RepositoryError.notAuthenticated
            }
            let record = try await requireLocalSession(accountID: session.accountID)
            localRecord = record
            refreshToken = record.refreshToken
        } else {
            localRecord = nil
            do {
                let data = try await keychain.getSecret(
                    account: AppShared.KeychainAccount.refreshToken(accountID: session.accountID)
                )
                refreshToken = data.flatMap { String(data: $0, encoding: .utf8) }
            } catch { throw RepositoryError.authenticationFailed }
        }
        try requireCurrentSession(accountID: session.accountID,
                                  generation: expectedSessionGeneration)
        guard let refreshToken else {
            throw RepositoryError.notAuthenticated
        }

        guard !isTransitioningAuthentication else { throw RepositoryError.notAuthenticated }
        try Task.checkCancellation()
        let tokenResponse: TokenResponse
        do {
            tokenResponse = try await api.refresh(refreshToken: refreshToken, server: server,
                                                  accountID: session.accountID, contextID: contextID,
                                                  installAccessToken: false)
        } catch NetworkingError.http(status: 400, body: let body) where Self.isInvalidRefreshGrant(body) {
            await revokeChangedAccount(for: lease)
            throw RepositoryError.reauthenticationRequired
        } catch { throw RepositoryError.network(error) }
        if Self.hasChangedUnlock(previousKey: session.protectedUserKey, currentKey: tokenResponse.key) ||
            (tokenResponse.kdf.map { $0 != 0 } ?? false) ||
            (tokenResponse.kdfIterations.map { $0 != session.kdfIterations } ?? false) {
            await revokeChangedAccount(for: lease)
            throw RepositoryError.reauthenticationRequired
        }

        // A server may already have rotated the refresh token. Keep the replacement for
        // the same saved session, but never publish a bearer after the vault was locked.
        do {
            try await loginCommitCoordinator.withLock {
                try await self.persistRefresh(tokenResponse.refreshToken, previous: refreshToken,
                                              localRecord: localRecord, accountID: session.accountID,
                                              authenticationIntent: authenticationIntent)
                try await self.publishRefreshBearer(tokenResponse, accountID: session.accountID,
                                                    contextID: contextID, generation: expectedSessionGeneration)
            }
        } catch {
            try? await api.setAccessToken(nil, for: session.accountID, contextID: contextID)
            throw error
        }
        return true
    }

    private func persistRefresh(_ replacement: String?, previous: String, localRecord: LocalVaultSession?,
                                accountID: String, authenticationIntent: UInt64) async throws {
        guard !isTransitioningAuthentication, session?.accountID == accountID,
              authenticationIntentGeneration == authenticationIntent else { throw RepositoryError.notAuthenticated }
        if let localRecord {
            do {
                if let replacement {
                    guard try await store.updateLocalVaultRefreshToken(replacement, accountID: accountID,
                                                                        sessionID: localRecord.id, expectedToken: previous) else {
                        throw RepositoryError.notAuthenticated
                    }
                } else {
                    guard try await requireLocalSession(accountID: accountID).refreshToken == previous else {
                        throw RepositoryError.notAuthenticated
                    }
                }
            } catch let error as RepositoryError { throw error }
            catch { throw RepositoryError.store(error) }
        } else if let replacement {
            do {
                try await keychain.setSecret(Data(replacement.utf8),
                                             account: AppShared.KeychainAccount.refreshToken(accountID: accountID),
                                             biometryGated: false)
            } catch { throw RepositoryError.authenticationFailed }
        }
    }

    private func publishRefreshBearer(_ response: TokenResponse, accountID: String, contextID: UUID,
                                      generation: UInt64) async throws {
        try Task.checkCancellation()
        let expected = AccountSessionLease(accountID: accountID, generation: generation)
        guard await unlockedSessionLease() == expected else { throw RepositoryError.locked }
        do {
            try await api.installAccessToken(response.accessToken, expiresIn: response.expiresIn,
                                             for: accountID, contextID: contextID)
        } catch { throw RepositoryError.network(error) }
        guard currentSessionLease() == expected else { throw RepositoryError.notAuthenticated }
    }

    /// Lock the vault: zero the in-memory key material (both the `KeyVault` and the
    /// write-path encryptor). The session + persisted tokens remain so the user can
    /// re-unlock without a full login.
    public func lock() async {
        await loginCommitCoordinator.withLock { await self.performLock() }
    }

    private func performLock() async {
        isLocking = true
        defer { isLocking = false }
        // Revoke decrypt/encrypt operations and biometric prompts that suspended under
        // the prior unlocked incarnation before clearing either key holder.
        if currentLoginAttemptID != nil { isTransitioningAuthentication = false }
        currentLoginAttemptID = nil
        pending = nil
        offeredWebAuthn = nil
        advanceSessionGeneration()
        autoFillAccess?.deactivate()
        if let accountID = session?.accountID, !isTransitioningAuthentication {
            let replacementContext = UUID()
            sessionAuthenticationContextID = replacementContext
            await api.bindAccount(accountID, contextID: replacementContext)
        }
        await keyVault.lock()
        await encryptor.clear()
        // Revoke the previous extension binding even if the extension did not observe
        // the closed gate. A new process cannot use a persisted nonce without a permit.
        if !usesLocalSessionStore {
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
        }
    }

    /// Whether the vault is currently unlocked.
    public func isUnlocked() async -> Bool {
        if usesLocalSessionStore { return await unlockedSessionLease() != nil }
        guard !isLocking, !isTransitioningAuthentication else { return false }
        return await keyVault.isUnlocked
    }

    public func hasSession() -> Bool {
        (usesLocalSessionStore || !isTransitioningAuthentication) && session != nil
    }

    /// Enable/disable biometric material for the current session without requiring a new
    /// login. Enabling is permitted only while the user key is already unlocked.
    public func setBiometricUnlockEnabled(_ enabled: Bool, expectedSession: AccountSessionLease? = nil) async throws {
        if let expectedSession, currentSessionLease() != expectedSession { throw RepositoryError.notAuthenticated }
        if usesLocalSessionStore {
            guard let localBiometrics else {
                if enabled { throw RepositoryError.authenticationFailed }
                return
            }
            guard let identity = localSessionIdentity, let lease = currentSessionLease(), lease.accountID == identity.accountID else {
                throw RepositoryError.notAuthenticated
            }
            biometricPolicyGeneration &+= 1
            let policyGeneration = biometricPolicyGeneration
            localBiometricPolicyChange = policyGeneration
            cancelLocalBiometricPrompt()
            defer {
                if localBiometricPolicyChange == policyGeneration { localBiometricPolicyChange = nil }
            }
            try await loginCommitCoordinator.withLock {
                try await self.changeLocalBiometricPolicy(enabled, wrapper: localBiometrics, identity: identity,
                                                          lease: lease, policyGeneration: policyGeneration)
            }
            return
        }
        biometricPolicyGeneration &+= 1
        let policyGeneration = biometricPolicyGeneration
        try await biometricPolicyCoordinator.withLock {
            try await self.performBiometricPolicyChange(
                enabled,
                policyGeneration: policyGeneration,
                expectedSession: expectedSession
            )
        }
    }

    public func localBiometricUnlockEnabled() async -> Bool {
        guard usesLocalSessionStore, localBiometrics != nil, let identity = localSessionIdentity,
              let lease = currentSessionLease(), lease.accountID == identity.accountID else { return false }
        let policyGeneration = biometricPolicyGeneration
        guard (try? await localBiometricEnvelope(for: identity)) != nil else { return false }
        return (try? requireLocalBiometricSession(identity, lease: lease, policyGeneration: policyGeneration)) != nil
    }

    private func changeLocalBiometricPolicy(
        _ enabled: Bool, wrapper: any LocalBiometricKeyWrapping, identity: LocalSessionIdentity,
        lease: AccountSessionLease, policyGeneration: UInt64
    ) async throws {
        try requireLocalBiometricSession(identity, lease: lease, policyGeneration: policyGeneration)
        let envelope: Data?
        if enabled {
            let userKey: SymmetricCryptoKey
            do { userKey = try await keyVault.userKeyForBiometricEnrollment() }
            catch { throw RepositoryError.locked }
            try requireLocalBiometricSession(identity, lease: lease, policyGeneration: policyGeneration)
            do { envelope = try wrapper.wrap(userKey, binding: identity.biometricBinding) }
            catch { throw RepositoryError.authenticationFailed }
        } else {
            envelope = nil
        }
        try requireLocalBiometricSession(identity, lease: lease, policyGeneration: policyGeneration)
        let updated: Bool
        do {
            updated = try await store.setLocalBiometricEnvelope(envelope, accountID: identity.accountID, sessionID: identity.id)
        } catch { throw RepositoryError.store(error) }
        guard updated else { throw RepositoryError.notAuthenticated }
        try requireLocalBiometricSession(identity, lease: lease, policyGeneration: policyGeneration)
    }

    private func performBiometricPolicyChange(
        _ enabled: Bool,
        policyGeneration: UInt64,
        expectedSession: AccountSessionLease?
    ) async throws {
        guard biometricPolicyGeneration == policyGeneration else { return }
        if let expectedSession, currentSessionLease() != expectedSession { throw RepositoryError.notAuthenticated }
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
        guard !isLocking, !isTransitioningAuthentication, let session,
              !usesLocalSessionStore || localSessionIdentity?.accountID == session.accountID else { return nil }
        return AccountSessionLease(
            accountID: session.accountID,
            generation: sessionGeneration
        )
    }

    public func unlockedSessionLease() async -> AccountSessionLease? {
        guard let lease = currentSessionLease(), await keyVault.isUnlocked,
              currentSessionLease() == lease else { return nil }
        return lease
    }

    #if os(macOS)
    public func sessionTimeoutLease(publishedBy eventTime: ContinuousClock.Instant,
                                    after publicationFloor: ContinuousClock.Instant? = nil) async -> AccountSessionLease? {
        if isLocking {
            return await loginCommitCoordinator.withLock {
                await self.publishedSessionLease(by: eventTime, after: publicationFloor)
            }
        }
        return publishedSessionLease(by: eventTime, after: publicationFloor)
    }

    private func publishedSessionLease(by eventTime: ContinuousClock.Instant,
                                       after publicationFloor: ContinuousClock.Instant? = nil) -> AccountSessionLease? {
        guard let sessionPublishedAt, sessionPublishedAt <= eventTime,
              publicationFloor.map({ sessionPublishedAt > $0 }) != false else { return nil }
        return currentSessionLease()
    }

    public func expireSession(_ lease: AccountSessionLease, logOut: Bool,
                              systemEventAt: ContinuousClock.Instant? = nil) async -> SessionTimeoutResult {
        if logOut {
            if let systemEventAt, isLocking {
                _ = await sessionTimeoutLease(publishedBy: systemEventAt)
            }
            guard let authorizedLease = timeoutLease(lease, systemEventAt: systemEventAt) else { return .superseded }
            let expectedIntent = authenticationIntentGeneration &+ 1
            let didLogOut = await logout(verifySharedRevocation: true, expectedSession: authorizedLease)
            guard authenticationIntentGeneration == expectedIntent else { return .superseded }
            return didLogOut ? .loggedOut : .logoutFailedLocked
        }
        return await loginCommitCoordinator.withLock {
            await self.lockIfCurrent(lease, systemEventAt: systemEventAt)
        }
    }

    private func timeoutLease(_ expected: AccountSessionLease, systemEventAt: ContinuousClock.Instant?) -> AccountSessionLease? {
        if let systemEventAt {
            guard let current = publishedSessionLease(by: systemEventAt), current.accountID == expected.accountID else { return nil }
            return current
        }
        return currentSessionLease() == expected ? expected : nil
    }

    private func lockIfCurrent(_ expected: AccountSessionLease, systemEventAt: ContinuousClock.Instant?) async -> SessionTimeoutResult {
        guard let lease = timeoutLease(expected, systemEventAt: systemEventAt) else { return .superseded }
        await performLock()
        return session?.accountID == lease.accountID && sessionGeneration == lease.generation &+ 1
            ? .locked : .superseded
    }
    #endif

    public func sealPasskeyHandoff(_ bytes: Data, for lease: AccountSessionLease) async throws -> EncString {
        guard await unlockedSessionLease() == lease else { throw RepositoryError.locked }
        let envelope = try await keyVault.sealPasskeyHandoff(bytes)
        guard await unlockedSessionLease() == lease else { throw RepositoryError.locked }
        return envelope
    }

    public func openPasskeyHandoff(_ envelope: EncString, for lease: AccountSessionLease) async throws -> Data {
        guard await unlockedSessionLease() == lease else { throw RepositoryError.locked }
        var bytes = try await keyVault.openPasskeyHandoff(envelope)
        guard await unlockedSessionLease() == lease else {
            bytes.withUnsafeMutableBytes(SecureBytes.erase)
            throw RepositoryError.locked
        }
        return bytes
    }

    public func verifyMasterPassword(_ password: String, for lease: AccountSessionLease) async throws {
        _ = try await authorizeAccountAction(for: lease, password: password)
    }

    package func accountActionContext(for lease: AccountSessionLease) async throws -> UUID {
        try await ensureAccessToken(for: lease)
        guard await unlockedSessionLease() == lease, let context = sessionAuthenticationContextID else {
            throw RepositoryError.locked
        }
        return context
    }

    package func authorizeAccountAction(for lease: AccountSessionLease, password: String) async throws -> String {
        guard await unlockedSessionLease() == lease, let session else { throw RepositoryError.locked }
        do {
            let protected = try EncString(parsing: session.protectedUserKey)
            var key = try KDF.deriveMasterKey(password: password, email: session.email, iterations: session.kdfIterations)
            defer { key.withUnsafeMutableBytes(SecureBytes.erase) }
            _ = try Self.decryptUserKey(masterKey: key, protectedKey: protected)
            return try KDF.masterPasswordHash(masterKey: key, password: password, purpose: .serverAuthorization)
        } catch { throw RepositoryError.authenticationFailed }
    }

    /// Full logout: lock, clear the session, drop the bearer token, and delete persisted
    /// secrets + biometric unlock.
    @discardableResult
    public func logout(reservedIntent: UInt64? = nil) async -> Bool {
        await logout(reservedIntent: reservedIntent, expectedSession: nil)
    }

    package func logout(reservedIntent: UInt64? = nil, expectedSession: AccountSessionLease?) async -> Bool {
        #if os(macOS)
        await logout(reservedIntent: reservedIntent, verifySharedRevocation: true, expectedSession: expectedSession)
        #else
        await logout(reservedIntent: reservedIntent, verifySharedRevocation: false, expectedSession: expectedSession)
        #endif
    }

    private func logout(reservedIntent: UInt64? = nil, verifySharedRevocation: Bool,
                        expectedSession: AccountSessionLease? = nil) async -> Bool {
        if let expectedSession, currentSessionLease() != expectedSession { return false }
        let logoutIntent: UInt64
        if let reservedIntent {
            guard authenticationIntentGeneration == reservedIntent else { return false }
            logoutIntent = reservedIntent
        } else {
            authenticationIntentGeneration &+= 1
            biometricPolicyGeneration &+= 1
            logoutIntent = authenticationIntentGeneration
        }
        autoFillAccess?.deactivate()
        isTransitioningAuthentication = true
        let cleanupLease: LogoutCleanupLease?
        if let accountID = session?.accountID ?? completingAccountID ?? localSessionIdentity?.accountID {
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
        if !usesLocalSessionStore && !verifySharedRevocation {
            session = nil
            sessionAuthenticationContextID = nil
        }
        pending = nil
        offeredWebAuthn = nil
        currentLoginAttemptID = nil
        currentLoginIntentGeneration = logoutIntent
        activeTwoFactorSubmissionID = nil
        advanceSessionGeneration()
        if usesLocalSessionStore {
            return await loginCommitCoordinator.withLock {
                await self.performLocalLogoutCleanup(cleanupLease, intent: logoutIntent)
            }
        }
        // Login commit and logout cleanup both mutate the same Keychain/API account state.
        // Serializing them prevents a stale same-account delete from landing after a newer
        // login has written its refresh/local-auth secrets.
        return await loginCommitCoordinator.withLock {
            if verifySharedRevocation, !(await self.verifySharedLogoutRevocation(cleanupLease, intent: logoutIntent)) {
                return false
            }
            await self.performLogoutCleanup(cleanupLease, intent: logoutIntent,
                                            alreadyRevoked: verifySharedRevocation)
            return await self.isLogoutComplete(intent: logoutIntent)
        }
    }

    private func isLogoutComplete(intent: UInt64) -> Bool {
        authenticationIntentGeneration == intent && !isTransitioningAuthentication
    }

    // MARK: - Helpers

    private func performLocalLogoutCleanup(_ cleanupLease: LogoutCleanupLease?, intent logoutIntent: UInt64) async -> Bool {
        guard authenticationIntentGeneration == logoutIntent else { return false }
        await keyVault.lock()
        guard authenticationIntentGeneration == logoutIntent else { return false }
        await encryptor.clear()
        guard authenticationIntentGeneration == logoutIntent else { return false }

        let expectedIdentity = localSessionIdentity
        let revoked: Bool
        do {
            if let identity = expectedIdentity {
                if try await store.removeLocalVaultSession(accountID: identity.accountID, sessionID: identity.id) {
                    revoked = true
                } else {
                    revoked = try await store.localVaultSession() == nil
                }
                if revoked { localSessionIdentity = nil }
            } else {
                revoked = try await store.localVaultSession() == nil
            }
        } catch {
            revoked = false
        }
        guard authenticationIntentGeneration == logoutIntent else { return false }
        guard revoked else {
            if let cleanupLease, let contextID = cleanupLease.authenticationContextID {
                try? await api.setAccessToken(nil, for: cleanupLease.accountID, contextID: contextID)
                guard authenticationIntentGeneration == logoutIntent else { return false }
            }
            isTransitioningAuthentication = false
            return false
        }

        session = nil
        sessionAuthenticationContextID = nil
        if let cleanupLease, let contextID = cleanupLease.authenticationContextID {
            await api.clearAccountContext(accountID: cleanupLease.accountID, contextID: contextID)
            guard authenticationIntentGeneration == logoutIntent else { return false }
        }
        if let accountID = expectedIdentity?.accountID ?? cleanupLease?.accountID {
            try? await store.clearSendCache(accountID: accountID)
            guard authenticationIntentGeneration == logoutIntent else { return false }
            try? await store.clearGenerationHistory(accountID: accountID)
            guard authenticationIntentGeneration == logoutIntent else { return false }
        }
        if pendingLogoutCleanup?.id == cleanupLease?.id { pendingLogoutCleanup = nil }
        isTransitioningAuthentication = false
        return true
    }

    private func performLogoutCleanup(
        _ cleanupLease: LogoutCleanupLease?,
        intent logoutIntent: UInt64,
        alreadyRevoked: Bool
    ) async {
        guard authenticationIntentGeneration == logoutIntent else { return }
        // Cross-process revocation is the logout linearization point. Withdraw the
        // extension nonce/account before slower in-process/API cleanup awaits.
        if !alreadyRevoked {
            await keychain.deleteSecret(account: AppShared.KeychainAccount.activeSessionID)
            guard authenticationIntentGeneration == logoutIntent else { return }
            await keychain.deleteSecret(account: AppShared.KeychainAccount.activeAccountID)
            guard authenticationIntentGeneration == logoutIntent else { return }
            await keyVault.lock()
            guard authenticationIntentGeneration == logoutIntent else { return }
            await encryptor.clear()
            guard authenticationIntentGeneration == logoutIntent else { return }
        }
        if let accountID = cleanupLease?.accountID,
           let authenticationContextID = cleanupLease?.authenticationContextID {
            await api.clearAccountContext(
                accountID: accountID,
                contextID: authenticationContextID
            )
            guard authenticationIntentGeneration == logoutIntent else { return }
        }
        if let accountID = cleanupLease?.accountID {
            try? await store.clearSendCache(accountID: accountID)
            guard authenticationIntentGeneration == logoutIntent else { return }
            try? await store.clearGenerationHistory(accountID: accountID)
            guard authenticationIntentGeneration == logoutIntent else { return }
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

    private func verifySharedLogoutRevocation(_ cleanupLease: LogoutCleanupLease?, intent: UInt64) async -> Bool {
        guard authenticationIntentGeneration == intent else { return false }
        await keyVault.lock()
        guard authenticationIntentGeneration == intent else { return false }
        await encryptor.clear()
        guard authenticationIntentGeneration == intent else { return false }
        await keychain.deleteSecret(account: AppShared.KeychainAccount.activeSessionID)
        guard authenticationIntentGeneration == intent else { return false }
        await keychain.deleteSecret(account: AppShared.KeychainAccount.activeAccountID)
        guard authenticationIntentGeneration == intent else { return false }

        let removed: Bool
        do {
            let accountMarker = try await keychain.getSecret(account: AppShared.KeychainAccount.activeAccountID)
            guard authenticationIntentGeneration == intent else { return false }
            let sessionMarker = try await keychain.getSecret(account: AppShared.KeychainAccount.activeSessionID)
            removed = accountMarker == nil && sessionMarker == nil
        } catch {
            removed = false
        }
        guard authenticationIntentGeneration == intent else { return false }
        if removed {
            session = nil
            sessionAuthenticationContextID = nil
        } else {
            if let cleanupLease, let contextID = cleanupLease.authenticationContextID {
                try? await api.setAccessToken(nil, for: cleanupLease.accountID, contextID: contextID)
                guard authenticationIntentGeneration == intent else { return false }
            }
            isTransitioningAuthentication = false
        }
        return removed
    }

    /// A terminal failure from the initial password grant is no longer an authentication
    /// transition. Only the still-current attempt may reset these flags: an older request
    /// that resumes after being superseded must leave the newer intent untouched.
    private func expirePendingDeviceGrant(_ attemptID: UUID) async {
        await loginCommitCoordinator.withLock {
            await self.finishLoginFailureIfCurrent(attemptID)
        }
    }

    private func finishLoginFailureIfCurrent(_ attemptID: UUID) {
        guard isCurrentLoginAttempt(attemptID) else { return }
        pending = nil
        offeredWebAuthn = nil
        currentLoginAttemptID = nil
        activeTwoFactorSubmissionID = nil
        isTransitioningAuthentication = false
    }

    /// Undo durable/in-memory state written by a token response whose local commit failed.
    /// This runs while the login-commit coordinator is held, so a newer attempt may perform
    /// its network grant but cannot publish its session until this rollback has finished.
    private func rollbackFailedLoginCommitIfCurrent(_ pending: PendingLogin) async {
        let accountID = Self.accountID(server: pending.server, email: pending.email)
        if usesLocalSessionStore {
            await api.clearAccountContext(accountID: accountID, contextID: pending.attemptID)
            await keyVault.lock()
            await encryptor.clear()
            return
        }
        guard isCurrentLoginAttempt(pending.attemptID) else { return }

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
        try Task.checkCancellation()
        guard isCurrentLoginAttempt(attemptID) else {
            throw RepositoryError.underlying(
                kind: .network,
                description: "Login attempt was superseded"
            )
        }
    }

    private func requireCurrentSession(accountID: String, generation: UInt64) throws {
        guard session?.accountID == accountID,
              sessionGeneration == generation, !isLocking, !isTransitioningAuthentication else {
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
        cancelLocalBiometricPrompt()
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
        var masterKey = try KDF.deriveMasterKey(password: password, email: email, iterations: iterations)
        defer { masterKey.withUnsafeMutableBytes(SecureBytes.erase) }
        return try decryptUserKey(masterKey: masterKey, protectedKey: protectedKey)
    }

    private static func decryptUserKey(masterKey: [UInt8],
                                       protectedKey: EncString) throws -> SymmetricCryptoKey {
        try unwrapUserKey(protectedKey, using: KeyStretch.stretchMasterKey(masterKey))
    }

    private static func unwrapUserKey(_ protectedKey: EncString, using wrappingKey: SymmetricCryptoKey) throws -> SymmetricCryptoKey {
        var raw = try SymmetricCrypto.decrypt(protectedKey, using: wrappingKey)
        defer { raw.withUnsafeMutableBytes(SecureBytes.erase) }
        return try SymmetricCryptoKey(combined: raw)
    }

    package func checkRemoteAccountKey(_ remote: EncString?, for lease: AccountSessionLease) async throws {
        guard currentSessionLease() == lease, let session else { throw RepositoryError.locked }
        if Self.hasChangedUnlock(previousKey: session.protectedUserKey, currentKey: remote) {
            await revokeChangedAccount(for: lease)
            throw RepositoryError.reauthenticationRequired
        }
    }

    @discardableResult
    package func revokeChangedAccount(for lease: AccountSessionLease) async -> Bool {
        guard currentSessionLease() == lease else { return false }
        needsNewLogin = true
        let removed = await logout(expectedSession: lease)
        if !removed, session?.accountID == lease.accountID, needsNewLogin { await lock() }
        if needsNewLogin { await onUnlockInvalidated() }
        return removed
    }

    private static func isInvalidRefreshGrant(_ body: String) -> Bool {
        guard body.utf8.count <= 8_192,
              let payload = try? JSONSerialization.jsonObject(with: Data(body.utf8)) as? [String: Any] else { return false }
        return payload["error"] as? String == "invalid_grant"
    }

    static func hasChangedUnlock(previousKey: String, currentKey: EncString?) -> Bool {
        guard let currentKey, currentKey.type == .aesCbc256_HmacSha256_B64,
              currentKey.ciphertext.count == 80, currentKey.iv?.count == 16, currentKey.mac?.count == 32 else { return false }
        return currentKey.stringValue != previousKey
    }

    private static func sameUserKey(previousKey: String, current: SymmetricCryptoKey, wrappingKey: SymmetricCryptoKey?) -> Bool {
        guard let wrappingKey, let protected = try? EncString(parsing: previousKey),
              let previous = try? unwrapUserKey(protected, using: wrappingKey) else { return false }
        return previous == current
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
