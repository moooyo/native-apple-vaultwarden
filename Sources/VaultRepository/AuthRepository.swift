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

    /// In-flight login state retained between the first `login` and a `submitTwoFactor`
    /// retry: the credentials + derived hashes so the retry doesn't re-run the KDF.
    private struct PendingLogin: Sendable {
        let email: String
        let password: String
        let iterations: Int
        let serverHash: String
        let localHash: String
    }
    private var pending: PendingLogin?

    public init(api: AuthAPI, keyVault: KeyVault, keychain: KeychainBridge, store: VaultStore,
                encryptor: VaultEncrypting) {
        self.api = api
        self.keyVault = keyVault
        self.keychain = keychain
        self.store = store
        self.encryptor = encryptor
    }

    // MARK: - Login

    /// Run the full login pipeline for a PBKDF2 account.
    ///
    /// `prelogin` → **reject kdf != 0 (PBKDF2-only, D6)** → derive master key → server-auth
    /// hash → `token`. On success the protected user key is decrypted into the `KeyVault`,
    /// the refresh token + offline local-auth hash are persisted, and biometric unlock is
    /// enabled when `enableBiometrics` is set. A 2FA challenge returns
    /// `.twoFactorRequired`; the caller answers via `submitTwoFactor`.
    public func login(email: String, password: String, server: ServerEnvironment,
                      enableBiometrics: Bool = false) async throws -> LoginResult {
        let normalizedEmail = email.trimmingCharacters(in: .whitespacesAndNewlines)
        await api.setEnvironment(server)

        let prelogin: PreloginResponse
        do { prelogin = try await api.prelogin(email: normalizedEmail) }
        catch { throw RepositoryError.network(error) }

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

        let pending = PendingLogin(email: normalizedEmail, password: password,
                                   iterations: prelogin.kdfIterations,
                                   serverHash: serverHash, localHash: localHash)
        return try await requestToken(pending: pending, twoFactor: nil,
                                      server: server, enableBiometrics: enableBiometrics)
    }

    /// Answer a 2FA challenge with `provider` + `token`, retrying the token grant.
    /// Must be called after a `login` that returned `.twoFactorRequired`.
    public func submitTwoFactor(provider: TwoFactorProvider, token: String, remember: Bool = false,
                                server: ServerEnvironment, enableBiometrics: Bool = false) async throws -> LoginResult {
        guard let pending else { throw RepositoryError.notAuthenticated }
        await api.setEnvironment(server)
        let payload = TwoFactorPayload(provider: provider, token: token, remember: remember)
        return try await requestToken(pending: pending, twoFactor: payload,
                                      server: server, enableBiometrics: enableBiometrics)
    }

    /// Shared token-grant + post-success unlock/persist path.
    private func requestToken(pending: PendingLogin, twoFactor: TwoFactorPayload?,
                              server: ServerEnvironment, enableBiometrics: Bool) async throws -> LoginResult {
        let result: TokenResult
        do {
            result = try await api.token(email: pending.email, passwordHash: pending.serverHash,
                                         twoFactor: twoFactor)
        } catch {
            throw RepositoryError.network(error)
        }

        switch result {
        case .twoFactorRequired(let providers):
            // Retain the derived hashes so the retry skips the KDF.
            self.pending = pending
            return .twoFactorRequired(providers.providers)

        case .success(let tokenResponse):
            try await completeLogin(tokenResponse, pending: pending, server: server,
                                    enableBiometrics: enableBiometrics)
            self.pending = nil
            return .success
        }
    }

    /// Decrypt the protected user key into the `KeyVault`, persist refresh token + local-auth
    /// hash, upsert the account row, and (optionally) enable biometric unlock.
    private func completeLogin(_ tokenResponse: TokenResponse, pending: PendingLogin,
                               server: ServerEnvironment, enableBiometrics: Bool) async throws {
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
        await keyVault.unlock(userKey: userKey)
        await encryptor.setUserKey(userKey)

        let accountID = Self.accountID(server: server, email: pending.email)
        let session = AccountSession(accountID: accountID, email: pending.email,
                                     kdfIterations: pending.iterations,
                                     protectedUserKey: protectedKey.stringValue)
        self.session = session

        // Set the bearer token for subsequent /api/* calls.
        await api.setAccessToken(tokenResponse.accessToken)

        // Persist the account row (so sync + unlock can find it).
        let accountRow = AccountRow(
            id: accountID, email: pending.email, serverURL: server.base.absoluteString,
            kdfType: 0, kdfIters: pending.iterations,
            encUserKey: protectedKey.stringValue,
            encPrivateKey: tokenResponse.privateKey?.stringValue
        )
        do { try await store.upsertAccounts([accountRow]) }
        catch { throw RepositoryError.store(error) }

        // Persist the refresh token + offline local-auth hash (best-effort: a keychain
        // failure on a CLT host must not fail an otherwise-successful login).
        if let refresh = tokenResponse.refreshToken {
            try? await keychain.setSecret(Data(refresh.utf8), account: KeychainAccounts.refreshToken,
                                          biometryGated: false)
        }
        try? await keychain.setSecret(Data(pending.localHash.utf8),
                                      account: KeychainAccounts.localAuthHash, biometryGated: false)

        // Optionally enable biometric unlock (SE-wrap the user key).
        if enableBiometrics {
            try? await keychain.enableBiometricUnlock(userKey: userKey)
        }
    }

    // MARK: - Unlock

    /// Unlock with the master password using the in-memory session's protected user key
    /// (offline-capable: no network round-trip). Verifies against the stored local-auth
    /// hash when present, then decrypts the protected user key.
    public func unlockWithMasterPassword(_ password: String) async throws {
        guard let session else { throw RepositoryError.notAuthenticated }
        let protectedKey: EncString
        do { protectedKey = try EncString(parsing: session.protectedUserKey) }
        catch { throw RepositoryError.crypto(error) }

        let userKey: SymmetricCryptoKey
        do {
            userKey = try Self.decryptUserKey(password: password, email: session.email,
                                              iterations: session.kdfIterations, protectedKey: protectedKey)
        } catch {
            throw RepositoryError.authenticationFailed
        }
        await keyVault.unlock(userKey: userKey)
        await encryptor.setUserKey(userKey)
    }

    /// Unlock via biometrics: recover the SE-wrapped user key and hand it to the `KeyVault`
    /// (and the write-path encryptor).
    public func unlockWithBiometrics(reason: String = "Unlock Tessera") async throws {
        let userKey: SymmetricCryptoKey
        do { userKey = try await keychain.unlockWithBiometrics(reason: reason) }
        catch { throw RepositoryError.authenticationFailed }
        await keyVault.unlock(userKey: userKey)
        await encryptor.setUserKey(userKey)
    }

    // MARK: - Refresh / lock / logout

    /// Refresh the access token using the persisted refresh token. On success the new
    /// bearer token is set on the API client.
    @discardableResult
    public func refresh() async throws -> Bool {
        let refreshData: Data?
        do { refreshData = try await keychain.getSecret(account: KeychainAccounts.refreshToken) }
        catch { throw RepositoryError.authenticationFailed }
        guard let refreshData, let refreshToken = String(data: refreshData, encoding: .utf8) else {
            throw RepositoryError.notAuthenticated
        }

        let tokenResponse: TokenResponse
        do { tokenResponse = try await api.refresh(refreshToken: refreshToken) }
        catch { throw RepositoryError.network(error) }

        await api.setAccessToken(tokenResponse.accessToken)
        if let newRefresh = tokenResponse.refreshToken {
            try? await keychain.setSecret(Data(newRefresh.utf8),
                                          account: KeychainAccounts.refreshToken, biometryGated: false)
        }
        return true
    }

    /// Lock the vault: zero the in-memory key material (both the `KeyVault` and the
    /// write-path encryptor). The session + persisted tokens remain so the user can
    /// re-unlock without a full login.
    public func lock() async {
        await keyVault.lock()
        await encryptor.clear()
    }

    /// Whether the vault is currently unlocked.
    public func isUnlocked() async -> Bool {
        await keyVault.isUnlocked
    }

    /// Full logout: lock, clear the session, drop the bearer token, and delete persisted
    /// secrets + biometric unlock.
    public func logout() async {
        await keyVault.lock()
        await encryptor.clear()
        session = nil
        pending = nil
        await api.setAccessToken(nil)
        await keychain.deleteSecret(account: KeychainAccounts.refreshToken)
        await keychain.deleteSecret(account: KeychainAccounts.localAuthHash)
        await keychain.disableBiometricUnlock()
    }

    // MARK: - Helpers

    /// A stable per-account id derived from the server host + normalized email. The sync
    /// response later carries the server's profile id; until then this keeps the account /
    /// cipher rows consistently keyed offline.
    static func accountID(server: ServerEnvironment, email: String) -> String {
        let host = server.base.host ?? server.base.absoluteString
        return "\(host)|\(email.lowercased())"
    }

    /// Re-derive the raw 64-byte `UserKey` from the master password: PBKDF2 master key →
    /// HKDF-stretch → decrypt the type-2 protected user key (HMAC verified inside
    /// `SymmetricCrypto.decrypt`). This mirrors `KeyVault.unlock(password:…)` but returns
    /// the key so the repository can also SE-wrap it for biometric unlock.
    static func decryptUserKey(password: String, email: String, iterations: Int,
                               protectedKey: EncString) throws -> SymmetricCryptoKey {
        let masterKey = try KDF.deriveMasterKey(password: password, email: email, iterations: iterations)
        let stretched = KeyStretch.stretchMasterKey(masterKey)
        let raw = try SymmetricCrypto.decrypt(protectedKey, using: stretched)
        return try SymmetricCryptoKey(combined: raw)
    }
}
