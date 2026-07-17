import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import KeychainBridge
import Fido2
import Generators
import AppShared

/// The AutoFill extension's least-privilege read facade (design spec §5.7 / blueprint §F).
///
/// `VaultReader` is the ONLY vault API the extension links against. It deliberately offers
/// NO networking, NO sync, and NO bulk secret decryption: it can unlock via biometrics, scan a
/// bounded set of non-secret display metadata for the manual picker, then decrypt just the ONE
/// selected cipher's credential fields — enough to vend a password/OTP or build a passkey
/// assertion. Keeping the surface this small bounds the extension's link graph and plaintext
/// lifetime (the ~120MB extension memory red line).
///
/// An `actor` so all access is serialized; every decryption goes through the injected
/// `KeyVault`, so raw key bytes never reach this layer.
public actor VaultReader {
    private static let maximumRowsScanned = 200
    private static let maximumCandidateCount = 50
    private static let maximumFieldsPerCipher = 16
    private static let maximumRequestedServices = 32
    private static let maximumMetadataBytes = 4_096
    private static let maximumEncryptedBlobBytes = 131_072

    private let store: VaultStore
    private let keyVault: KeyVault
    private let keychain: KeychainBridge
    private struct SessionBinding: Sendable, Equatable {
        let accountID: String
        let sessionID: String
    }
    private var unlockedBinding: SessionBinding?

    public struct SessionLease: Sendable, Equatable {
        public let accountID: String
        public let sessionID: String

        fileprivate init(accountID: String, sessionID: String) {
            self.accountID = accountID
            self.sessionID = sessionID
        }
    }

    public init(store: VaultStore, keyVault: KeyVault, keychain: KeychainBridge) {
        self.store = store
        self.keyVault = keyVault
        self.keychain = keychain
    }

    // MARK: - Unlock

    /// Unlock the vault for this process using biometrics: recover the SE-ECIES-wrapped
    /// UserKey via the Keychain (Face ID / Touch ID / Optic ID) and hand it to the
    /// `KeyVault`. No KDF is re-run — the wrapped key is unwrapped directly.
    ///
    /// - Throws: the underlying `KeychainError` if biometric unlock is unavailable,
    ///   was never enabled, or the prompt is canceled.
    public func unlockWithBiometrics(reason: String) async throws {
        // The wrapped biometric key is process-global, while the encrypted database can
        // contain several accounts. Refuse to unwrap an old account's key after the app
        // switches accounts. This check intentionally happens before the biometric prompt.
        guard let activeAccountID = await accountMarker(
                  named: AppShared.KeychainAccount.activeAccountID
              ),
              let activeSessionID = await accountMarker(
                  named: AppShared.KeychainAccount.activeSessionID
              ),
              let biometricAccountID = await accountMarker(
                  named: AppShared.KeychainAccount.biometricAccountID
              ),
              activeAccountID == biometricAccountID else {
            await keyVault.lock()
            unlockedBinding = nil
            throw KeychainError.unavailable
        }

        let userKey = try await keychain.unlockWithBiometrics(reason: reason)

        // Close the cross-process race where the main app switches accounts while the
        // system biometric sheet is visible. Never install the recovered key unless both
        // bindings are still exactly the values checked above.
        guard await accountMarker(named: AppShared.KeychainAccount.activeAccountID)
                  == activeAccountID,
              await accountMarker(named: AppShared.KeychainAccount.activeSessionID)
                  == activeSessionID,
              await accountMarker(named: AppShared.KeychainAccount.biometricAccountID)
                  == biometricAccountID else {
            await keyVault.lock()
            unlockedBinding = nil
            throw KeychainError.unavailable
        }
        await keyVault.unlock(userKey: userKey)
        unlockedBinding = SessionBinding(
            accountID: activeAccountID,
            sessionID: activeSessionID
        )
    }

    /// Lease used by passkey registration, whose write-back happens after biometric unlock
    /// but does not otherwise read a cipher. It must enforce the same account/session nonce
    /// as assertion and password fulfillment.
    public func currentSessionLease() async throws -> SessionLease {
        guard let binding = unlockedBinding else { throw VaultReaderError.locked }
        try await requireCurrentBinding(accountID: binding.accountID)
        return SessionLease(
            accountID: binding.accountID,
            sessionID: binding.sessionID
        )
    }

    public func validateSessionLease(_ lease: SessionLease) async throws {
        guard unlockedBinding == SessionBinding(
            accountID: lease.accountID,
            sessionID: lease.sessionID
        ) else {
            throw VaultReaderError.notFound
        }
        try await requireCurrentBinding(accountID: lease.accountID)
    }

    /// Decode a system identity only when its opaque account tag matches the account that
    /// currently owns the unlocked key. Legacy raw UUID identifiers deliberately fail closed.
    private func validatedSystemCipherRow(
        forRecordIdentifier recordIdentifier: String,
        kind: CredentialRecordIdentifier.Kind,
        serviceIdentifier: String,
        user: String
    ) async throws -> CipherRow {
        let accountID = try await activeAccountID()
        guard let cipherID = CredentialRecordIdentifier.decode(
            recordIdentifier,
            expectedAccountID: accountID,
            expectedKind: kind,
            expectedServiceIdentifier: serviceIdentifier,
            expectedUser: user
        ) else {
            throw VaultReaderError.notFound
        }
        let resolvedID = try await store.resolveCipherID(cipherID, accountID: accountID)
        guard let row = try await store.cipher(id: resolvedID, accountID: accountID),
              row.deletedDate == nil,
              let login = ReaderBlob.parse(row.encBlob)?.login else {
            throw VaultReaderError.notFound
        }
        let cipherKey = try await resolveCipherKey(row)
        let loginUser = try await candidateDecrypt(
            login.username,
            cipherKey: cipherKey
        ) ?? ""
        let serviceIsCurrent: Bool
        switch kind {
        case .password:
            let matchesService = try await containsExactService(
                serviceIdentifier,
                uris: login.uris,
                cipherKey: cipherKey
            )
            serviceIsCurrent = login.password != nil && loginUser == user
                && matchesService
        case .oneTimeCode:
            let matchesService = try await containsExactService(
                serviceIdentifier,
                uris: login.uris,
                cipherKey: cipherKey
            )
            serviceIsCurrent = login.totp != nil && loginUser == user
                && matchesService
        case .passkey:
            let expectedRP = Self.normalizedRPID(serviceIdentifier)
            var matches = false
            for credential in (login.fido2Credentials ?? []).prefix(
                Self.maximumFieldsPerCipher
            ) {
                if let rpID = try await candidateDecrypt(
                    credential.rpId,
                    cipherKey: cipherKey
                ), Self.normalizedRPID(rpID) == expectedRP {
                    let passkeyUser = try await candidateDecrypt(
                        credential.userName,
                        cipherKey: cipherKey
                    ) ?? loginUser
                    guard passkeyUser == user else { continue }
                    matches = true
                    break
                }
            }
            serviceIsCurrent = expectedRP != nil && matches
        }
        guard serviceIsCurrent else { throw VaultReaderError.notFound }
        try await requireCurrentBinding(accountID: accountID)
        return row
    }

    public func cipherID(
        forRecordIdentifier recordIdentifier: String,
        kind: CredentialRecordIdentifier.Kind,
        serviceIdentifier: String,
        user: String
    ) async throws -> String {
        try await validatedSystemCipherRow(
            forRecordIdentifier: recordIdentifier,
            kind: kind,
            serviceIdentifier: serviceIdentifier,
            user: user
        ).id
    }

    /// Atomically validate the current system identity metadata against one row snapshot,
    /// then decrypt the password from that same snapshot.
    public func passwordCredential(
        forRecordIdentifier recordIdentifier: String,
        serviceIdentifier: String,
        user: String
    ) async throws -> (user: String, password: String) {
        let row = try await validatedSystemCipherRow(
            forRecordIdentifier: recordIdentifier,
            kind: .password,
            serviceIdentifier: serviceIdentifier,
            user: user
        )
        return try await passwordCredential(from: row)
    }

    public func oneTimeCode(
        forRecordIdentifier recordIdentifier: String,
        serviceIdentifier: String,
        user: String,
        at date: Date = Date()
    ) async throws -> String {
        let row = try await validatedSystemCipherRow(
            forRecordIdentifier: recordIdentifier,
            kind: .oneTimeCode,
            serviceIdentifier: serviceIdentifier,
            user: user
        )
        return try await oneTimeCode(from: row, at: date)
    }

    private func containsExactService(
        _ expected: String,
        uris: [ReaderBlob.Uri]?,
        cipherKey: SymmetricCryptoKey?
    ) async throws -> Bool {
        let expected = expected.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !expected.isEmpty else { return false }
        for uri in (uris ?? []).prefix(Self.maximumFieldsPerCipher) {
            if let value = try await candidateDecrypt(uri.uri, cipherKey: cipherKey),
               value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == expected {
                return true
            }
        }
        return false
    }

    // MARK: - Manual picker candidates

    /// Returns a bounded set of non-secret credential metadata for the extension's
    /// manual picker.
    ///
    /// The query is always scoped to the account named by the shared Keychain's
    /// `activeAccountID` marker. At most 200 recent live login rows are read from SQL,
    /// at most 16 URIs/passkeys are inspected per row, and `limit` is clamped to 50.
    /// Password/TOTP results whose URI matches `serviceIdentifiers` are ordered first;
    /// other entries remain available as bounded manual-picker fallbacks. When
    /// `relyingPartyIdentifier` is supplied, passkeys are strictly filtered to that RP.
    ///
    /// This decrypts only display metadata (name, username, URI/RP, credential id, and
    /// user handle). Passwords, TOTP seeds, and passkey private keys remain encrypted.
    public func credentialCandidates(
        kind: CredentialCandidate.Kind,
        serviceIdentifiers: [String] = [],
        relyingPartyIdentifier: String? = nil,
        limit: Int = 24
    ) async throws -> [CredentialCandidate] {
        let resultLimit = min(max(limit, 0), Self.maximumCandidateCount)
        guard resultLimit > 0 else { return [] }
        guard await keyVault.isUnlocked else { throw VaultReaderError.locked }

        let accountID = try await activeAccountID()
        let requestedServices = Self.serviceMatchKeys(for: serviceIdentifiers)
        let requiredRP: String?
        if let relyingPartyIdentifier {
            guard let normalized = Self.normalizedRPID(relyingPartyIdentifier) else {
                return []
            }
            requiredRP = normalized
        } else {
            requiredRP = nil
        }

        let rows = try await store.recentLoginCiphers(
            accountID: accountID,
            limit: Self.maximumRowsScanned,
            maximumBlobBytes: Self.maximumEncryptedBlobBytes
        )
        var preferred: [CredentialCandidate] = []
        var fallback: [CredentialCandidate] = []
        var seen = Set<CredentialCandidate.ID>()

        func retain(_ candidate: CredentialCandidate, isPreferred: Bool) {
            guard seen.insert(candidate.id).inserted else { return }
            if isPreferred {
                guard preferred.count < resultLimit else { return }
                preferred.append(candidate)
            } else {
                guard fallback.count < resultLimit else { return }
                fallback.append(candidate)
            }
        }

        for row in rows {
            guard let login = ReaderBlob.parse(row.encBlob)?.login else { continue }
            let cipherKey: SymmetricCryptoKey?
            do {
                cipherKey = try await resolveCipherKey(row)
            } catch VaultReaderError.locked {
                throw VaultReaderError.locked
            } catch {
                continue
            }

            guard let name = try await candidateDecrypt(row.encName, cipherKey: cipherKey) else {
                continue
            }

            switch kind {
            case .password:
                guard login.password != nil else { continue }
                // Password-only entries without a username are valid Bitwarden logins;
                // show them with an empty user label instead of making them undiscoverable.
                let user = try await candidateDecrypt(
                    login.username,
                    cipherKey: cipherKey
                ) ?? ""
                let service = try await preferredService(
                    from: login.uris,
                    requestedServices: requestedServices,
                    cipherKey: cipherKey
                )
                retain(
                    CredentialCandidate(
                        kind: .password,
                        name: name,
                        user: user,
                        recordID: row.id,
                        serviceIdentifier: service.value
                    ),
                    isPreferred: requestedServices.isEmpty || service.matchesRequest
                )

            case .oneTimeCode:
                guard login.totp != nil else { continue }
                let user = try await candidateDecrypt(login.username, cipherKey: cipherKey) ?? ""
                let service = try await preferredService(
                    from: login.uris,
                    requestedServices: requestedServices,
                    cipherKey: cipherKey
                )
                retain(
                    CredentialCandidate(
                        kind: .oneTimeCode,
                        name: name,
                        user: user,
                        recordID: row.id,
                        serviceIdentifier: service.value
                    ),
                    isPreferred: requestedServices.isEmpty || service.matchesRequest
                )

            case .passkey:
                let fallbackUser = try await candidateDecrypt(
                    login.username,
                    cipherKey: cipherKey
                ) ?? ""
                for credential in (login.fido2Credentials ?? []).prefix(
                    Self.maximumFieldsPerCipher
                ) {
                    // A picker entry without the private-key field could never fulfill an
                    // assertion, but the field itself is deliberately not decrypted here.
                    guard credential.keyValue != nil,
                          let rpID = try await candidateDecrypt(
                              credential.rpId,
                              cipherKey: cipherKey
                          ),
                          let normalizedRP = Self.normalizedRPID(rpID),
                          requiredRP == nil || normalizedRP == requiredRP,
                          let encodedCredentialID = try await candidateDecrypt(
                              credential.credentialId,
                              cipherKey: cipherKey
                          ),
                          let credentialID = Self.decodeCredentialID(encodedCredentialID),
                          let encodedUserHandle = try await candidateDecrypt(
                              credential.userHandle,
                              cipherKey: cipherKey
                          ),
                          let userHandle = Self.decodeBase64URL(encodedUserHandle) else {
                        continue
                    }
                    let user = try await candidateDecrypt(
                        credential.userName,
                        cipherKey: cipherKey
                    ) ?? fallbackUser
                    let matchesRequest = requestedServices.isEmpty
                        || !Self.serviceMatchKeys(for: rpID).isDisjoint(
                            with: requestedServices
                        )
                    retain(
                        CredentialCandidate(
                            kind: .passkey,
                            name: name,
                            user: user,
                            recordID: row.id,
                            serviceIdentifier: rpID,
                            credentialID: credentialID,
                            userHandle: userHandle
                        ),
                        isPreferred: requiredRP != nil || matchesRequest
                    )
                }
            }

            // Once the preferred bucket fills the result, later fallback rows cannot
            // affect ordering. Stop decrypting metadata even if the SQL scan had room.
            if preferred.count >= resultLimit { break }
        }

        // Do not return metadata if the app switched accounts during the scan.
        try await requireCurrentBinding(accountID: accountID)

        var result = preferred
        if result.count < resultLimit {
            result.append(contentsOf: fallback.prefix(resultLimit - result.count))
        }
        return result
    }

    private func validatedManualCandidateRow(
        _ candidate: CredentialCandidate
    ) async throws -> CipherRow {
        let row = try await fetchRow(candidate.recordID)
        guard let login = ReaderBlob.parse(row.encBlob)?.login else {
            throw VaultReaderError.notFound
        }
        let cipherKey = try await resolveCipherKey(row)
        let loginUser = try await candidateDecrypt(login.username, cipherKey: cipherKey) ?? ""

        switch candidate.kind {
        case .password, .oneTimeCode:
            guard loginUser == candidate.user,
                  (candidate.kind != .password || login.password != nil),
                  (candidate.kind != .oneTimeCode || login.totp != nil),
                  try await manualServiceStillMatches(
                      candidate.serviceIdentifier,
                      uris: login.uris,
                      cipherKey: cipherKey
                  ) else {
                throw VaultReaderError.notFound
            }
        case .passkey:
            guard let credentialID = candidate.credentialID,
                  let expectedHandle = candidate.userHandle,
                  let chosen = await matchingCredential(
                      login.fido2Credentials ?? [],
                      rpId: candidate.serviceIdentifier,
                      credentialID: credentialID,
                      cipherKey: cipherKey
                  ),
                  let encodedHandle = try await candidateDecrypt(
                      chosen.userHandle,
                      cipherKey: cipherKey
                  ), Self.decodeBase64URL(encodedHandle) == expectedHandle else {
                throw VaultReaderError.notFound
            }
            let currentUser = try await candidateDecrypt(
                chosen.userName,
                cipherKey: cipherKey
            ) ?? loginUser
            guard currentUser == candidate.user else { throw VaultReaderError.notFound }
        }
        try await requireCurrentBinding(accountID: row.accountID)
        return row
    }

    private func manualServiceStillMatches(
        _ service: String,
        uris: [ReaderBlob.Uri]?,
        cipherKey: SymmetricCryptoKey?
    ) async throws -> Bool {
        if !service.isEmpty {
            return try await containsExactService(
                service,
                uris: uris,
                cipherKey: cipherKey
            )
        }
        for uri in (uris ?? []).prefix(Self.maximumFieldsPerCipher) {
            if let value = try await candidateDecrypt(uri.uri, cipherKey: cipherKey),
               !value.isEmpty {
                return false
            }
        }
        return true
    }

    public func passwordCredential(
        for candidate: CredentialCandidate
    ) async throws -> (user: String, password: String) {
        guard candidate.kind == .password else { throw VaultReaderError.notFound }
        let row = try await validatedManualCandidateRow(candidate)
        return try await passwordCredential(from: row)
    }

    public func oneTimeCode(
        for candidate: CredentialCandidate,
        at date: Date = Date()
    ) async throws -> String {
        guard candidate.kind == .oneTimeCode else { throw VaultReaderError.notFound }
        let row = try await validatedManualCandidateRow(candidate)
        return try await oneTimeCode(from: row, at: date)
    }

    // MARK: - Password credential

    /// Decrypt and return the username + password for the single login cipher `recordID`.
    ///
    /// Fetches exactly one row, resolves the optional per-cipher key from `enc_cipher_key`,
    /// and decrypts only that item's login username/password.
    ///
    /// - Throws: `.locked` if the vault is locked, `.notFound` if no such cipher,
    ///   `.noPasswordField` if it is not a login with a username+password, `.malformed`
    ///   if the stored blob/EncStrings can't be parsed.
    public func passwordCredential(for recordID: String) async throws -> (user: String, password: String) {
        guard await keyVault.isUnlocked else { throw VaultReaderError.locked }
        let row = try await fetchRow(recordID)
        return try await passwordCredential(from: row)
    }

    private func passwordCredential(
        from row: CipherRow
    ) async throws -> (user: String, password: String) {
        guard let login = ReaderBlob.parse(row.encBlob)?.login else {
            throw VaultReaderError.noPasswordField
        }
        guard let passWire = login.password else {
            throw VaultReaderError.noPasswordField
        }

        let cipherKey = try await resolveCipherKey(row)
        let user: String
        if let userWire = login.username {
            user = try await decryptWire(userWire, cipherKey: cipherKey)
        } else {
            user = ""
        }
        let password = try await decryptWire(passWire, cipherKey: cipherKey)
        try await requireCurrentBinding(accountID: row.accountID)
        return (user, password)
    }

    // MARK: - One-time-code credential

    /// Decrypt the selected login's Bitwarden TOTP value and generate its code at `date`.
    /// The explicit date parameter is a clock seam for deterministic tests; production
    /// callers use the default current time.
    public func oneTimeCode(for recordID: String, at date: Date = Date()) async throws -> String {
        guard await keyVault.isUnlocked else { throw VaultReaderError.locked }
        let row = try await fetchRow(recordID)
        return try await oneTimeCode(from: row, at: date)
    }

    private func oneTimeCode(from row: CipherRow, at date: Date) async throws -> String {
        guard let totpWire = ReaderBlob.parse(row.encBlob)?.login?.totp else {
            throw VaultReaderError.noOneTimeCode
        }
        let cipherKey = try await resolveCipherKey(row)
        let storedValue = try await decryptWire(totpWire, cipherKey: cipherKey)
        let code: String
        do {
            let configuration = try TOTP.configuration(from: storedValue)
            code = TOTP.code(for: configuration, at: date)
        } catch {
            throw VaultReaderError.malformed
        }
        try await requireCurrentBinding(accountID: row.accountID)
        return code
    }

    // MARK: - Passkey assertion

    /// Build a WebAuthn assertion for the FIDO2 credential on cipher `recordID`.
    ///
    /// Finds the credential whose decrypted RP id and credential id both match the request,
    /// decodes its base64url-encoded PKCS#8 `keyValue`, and signs
    /// `(authenticatorData || clientDataHash)` via `Fido2Authenticator.assert`.
    ///
    /// The returned `signCount` is the stored counter (or 0). Persisting an incremented
    /// counter is a write path owned by the app/sync layer, not this read-only facade.
    ///
    /// - Throws: `.locked`, `.notFound`, `.noPasskey` (no credential / no decryptable
    ///   key), `.malformed` (bad PKCS#8 / counter).
    public func passkeyAssertion(recordID: String,
                                 rpId: String,
                                 credentialID: Data,
                                 clientDataHash: Data,
                                 userVerified: Bool) async throws
        -> (authenticatorData: Data, signature: Data) {
        guard await keyVault.isUnlocked else { throw VaultReaderError.locked }
        let row = try await fetchRow(recordID)
        return try await passkeyAssertion(
            from: row,
            rpId: rpId,
            credentialID: credentialID,
            expectedUserHandle: nil,
            clientDataHash: clientDataHash,
            userVerified: userVerified
        )
    }

    private func passkeyAssertion(
        from row: CipherRow,
        rpId: String,
        credentialID: Data,
        expectedUserHandle: Data?,
        clientDataHash: Data,
        userVerified: Bool
    ) async throws -> (authenticatorData: Data, signature: Data) {
        guard let credentials = ReaderBlob.parse(row.encBlob)?.login?.fido2Credentials,
              !credentials.isEmpty else {
            throw VaultReaderError.noPasskey
        }
        let cipherKey = try await resolveCipherKey(row)

        guard let chosen = await matchingCredential(
            credentials,
            rpId: rpId,
            credentialID: credentialID,
            cipherKey: cipherKey
        ) else {
            throw VaultReaderError.noPasskey
        }

        if let expectedUserHandle {
            guard let encodedHandle = try await candidateDecrypt(
                chosen.userHandle,
                cipherKey: cipherKey
            ), Self.decodeBase64URL(encodedHandle) == expectedUserHandle else {
                throw VaultReaderError.noPasskey
            }
        }

        guard let keyWire = chosen.keyValue else { throw VaultReaderError.noPasskey }
        let decryptedKeyValue: Data
        do {
            decryptedKeyValue = try await decryptWireData(keyWire, cipherKey: cipherKey)
        } catch VaultReaderError.locked {
            throw VaultReaderError.locked
        } catch {
            throw VaultReaderError.malformed
        }

        let credentialKey: CredentialKey
        if let encoded = String(data: decryptedKeyValue, encoding: .utf8),
           let pkcs8 = Self.decodeBase64URL(encoded),
           let decodedKey = try? CredentialKey(pkcs8: pkcs8) {
            credentialKey = decodedKey
        } else if let legacyKey = try? CredentialKey(pkcs8: decryptedKeyValue) {
            // Compatibility with early Tessera test/local data, which encrypted raw DER
            // instead of Bitwarden's base64url plaintext representation.
            credentialKey = legacyKey
        } else {
            throw VaultReaderError.malformed
        }

        let signCount = await decodeSignCount(chosen.counter, cipherKey: cipherKey)

        let result: (authenticatorData: Data, signature: Data)
        do {
            result = try Fido2Authenticator.assert(
                rpId: rpId,
                clientDataHash: clientDataHash,
                signCount: signCount,
                userVerified: userVerified,
                key: credentialKey
            )
        } catch {
            throw VaultReaderError.malformed
        }
        try await requireCurrentBinding(accountID: row.accountID)
        return result
    }

    public func passkeyAssertion(
        forRecordIdentifier recordIdentifier: String,
        serviceIdentifier: String,
        user: String,
        credentialID: Data,
        userHandle: Data,
        clientDataHash: Data,
        userVerified: Bool
    ) async throws -> (authenticatorData: Data, signature: Data) {
        let row = try await validatedSystemCipherRow(
            forRecordIdentifier: recordIdentifier,
            kind: .passkey,
            serviceIdentifier: serviceIdentifier,
            user: user
        )
        return try await passkeyAssertion(
            from: row,
            rpId: serviceIdentifier,
            credentialID: credentialID,
            expectedUserHandle: userHandle,
            clientDataHash: clientDataHash,
            userVerified: userVerified
        )
    }

    public func passkeyAssertion(
        for candidate: CredentialCandidate,
        relyingPartyIdentifier: String,
        clientDataHash: Data,
        userVerified: Bool
    ) async throws -> (authenticatorData: Data, signature: Data) {
        guard candidate.kind == .passkey,
              let credentialID = candidate.credentialID,
              let userHandle = candidate.userHandle,
              Self.normalizedRPID(candidate.serviceIdentifier)
                == Self.normalizedRPID(relyingPartyIdentifier) else {
            throw VaultReaderError.noPasskey
        }
        let row = try await validatedManualCandidateRow(candidate)
        return try await passkeyAssertion(
            from: row,
            rpId: relyingPartyIdentifier,
            credentialID: credentialID,
            expectedUserHandle: userHandle,
            clientDataHash: clientDataHash,
            userVerified: userVerified
        )
    }

    // MARK: - Decrypt one cipher

    /// Decrypt the single cipher `id` into a `DecryptedCipher` value (name + login fields).
    /// Only this one cipher is touched. Non-login ciphers decrypt with an empty
    /// login-field set (just `name`).
    ///
    /// - Throws: `.locked`, `.notFound`, `.malformed` (un-parseable name EncString).
    public func decryptOneCipher(id: String) async throws -> DecryptedCipher {
        guard await keyVault.isUnlocked else { throw VaultReaderError.locked }
        let row = try await fetchRow(id)
        let cipherKey = try await resolveCipherKey(row)

        // `name` is the one field expected on every cipher; a parse/decrypt failure here is
        // a corrupt row.
        guard let nameWire = row.encName else { throw VaultReaderError.malformed }
        let name = try await decryptWire(nameWire, cipherKey: cipherKey)

        let login = ReaderBlob.parse(row.encBlob)?.login
        let username = await optionalDecrypt(login?.username, cipherKey: cipherKey)
        let password = await optionalDecrypt(login?.password, cipherKey: cipherKey)
        let totp = await optionalDecrypt(login?.totp, cipherKey: cipherKey)

        var uris: [String] = []
        for uri in login?.uris ?? [] {
            if let u = await optionalDecrypt(uri.uri, cipherKey: cipherKey) { uris.append(u) }
        }

        let result = DecryptedCipher(
            id: row.id,
            type: row.type,
            name: name,
            username: username,
            password: password,
            totp: totp,
            uris: uris
        )
        try await requireCurrentBinding(accountID: row.accountID)
        return result
    }

    // MARK: - Private helpers

    /// Fetch a row from the store, mapping missing and foreign-account rows to the same
    /// `.notFound` result. This prevents a stale system identity from crossing accounts
    /// after the user switches profiles in the main app.
    private func fetchRow(_ id: String) async throws -> CipherRow {
        let accountID = try await activeAccountID()
        let resolvedID = try await store.resolveCipherID(id, accountID: accountID)
        guard let row = try await store.cipher(id: resolvedID, accountID: accountID),
              row.deletedDate == nil else {
            throw VaultReaderError.notFound
        }
        try await requireCurrentBinding(accountID: accountID)
        return row
    }

    /// Read the active-account marker without ever accepting malformed/oversized data.
    /// Keychain failures are deliberately indistinguishable from a missing marker so all
    /// read paths fail closed.
    private func activeAccountID() async throws -> String {
        guard let accountID = await accountMarker(
                  named: AppShared.KeychainAccount.activeAccountID
              ) else {
            throw VaultReaderError.notFound
        }
        try await requireCurrentBinding(accountID: accountID)
        return accountID
    }

    /// Validate the account + random session incarnation that authorized the in-memory key.
    /// `unlockedBinding == nil` is retained only for injected pre-unlocked test readers;
    /// production extension keys are installed exclusively by `unlockWithBiometrics` above.
    private func requireCurrentBinding(accountID: String) async throws {
        guard await keyVault.isUnlocked,
              let currentAccount = await accountMarker(
                  named: AppShared.KeychainAccount.activeAccountID
              ),
              let biometricAccount = await accountMarker(
                  named: AppShared.KeychainAccount.biometricAccountID
              ),
              let currentSession = await accountMarker(
                  named: AppShared.KeychainAccount.activeSessionID
              ),
              currentAccount == accountID,
              biometricAccount == accountID,
              unlockedBinding == nil || unlockedBinding == SessionBinding(
                  accountID: accountID,
                  sessionID: currentSession
              ) else {
            await keyVault.lock()
            unlockedBinding = nil
            throw VaultReaderError.notFound
        }
    }

    private func accountMarker(named account: String) async -> String? {
        guard let data = try? await keychain.getSecret(account: account),
              !data.isEmpty,
              data.count <= Self.maximumMetadataBytes,
              let value = String(data: data, encoding: .utf8),
              !value.isEmpty else {
            return nil
        }
        return value
    }

    /// Best-effort metadata decryption for picker rows. Corrupt optional metadata skips
    /// that candidate, while a concurrent vault lock is still surfaced to the caller.
    private func candidateDecrypt(
        _ wire: String?,
        cipherKey: SymmetricCryptoKey?
    ) async throws -> String? {
        guard let wire else { return nil }
        do {
            let value = try await decryptWire(wire, cipherKey: cipherKey)
            guard value.utf8.count <= Self.maximumMetadataBytes else { return nil }
            return value
        } catch VaultReaderError.locked {
            throw VaultReaderError.locked
        } catch {
            return nil
        }
    }

    /// Choose one display service per login. A matching URI wins; otherwise the first
    /// decryptable URI becomes the manual-picker fallback.
    private func preferredService(
        from uris: [ReaderBlob.Uri]?,
        requestedServices: Set<String>,
        cipherKey: SymmetricCryptoKey?
    ) async throws -> (value: String, matchesRequest: Bool) {
        var first = ""
        for uri in (uris ?? []).prefix(Self.maximumFieldsPerCipher) {
            guard let value = try await candidateDecrypt(uri.uri, cipherKey: cipherKey),
                  !value.isEmpty else {
                continue
            }
            if first.isEmpty { first = value }
            if !requestedServices.isEmpty,
               !Self.serviceMatchKeys(for: value).isDisjoint(with: requestedServices) {
                return (value, true)
            }
        }
        return (first, false)
    }

    /// Build conservative comparison keys. Exact raw values match, and URL/domain forms
    /// also match on an exact normalized host (never on a suffix).
    private static func serviceMatchKeys(for values: [String]) -> Set<String> {
        var result = Set<String>()
        for value in values.prefix(maximumRequestedServices) {
            let bounded = String(value.prefix(maximumMetadataBytes))
            result.formUnion(serviceMatchKeys(for: bounded))
        }
        return result
    }

    private static func serviceMatchKeys(for value: String) -> Set<String> {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return [] }
        let lowercased = trimmed.lowercased()
        var result: Set<String> = ["raw:\(lowercased)"]
        let parsed: URL?
        if lowercased.contains("://") {
            parsed = URL(string: lowercased)
        } else {
            parsed = URL(string: "https://\(lowercased)")
        }
        if var host = parsed?.host?.lowercased(), !host.isEmpty {
            while host.hasSuffix(".") { host.removeLast() }
            if !host.isEmpty { result.insert("host:\(host)") }
        }
        return result
    }

    /// WebAuthn RP ids compare as exact, case-insensitive DNS names. A URL-shaped caller
    /// input is accepted by extracting its host, but paths/ports are never part of an RP.
    private static func normalizedRPID(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        var normalized: String
        if trimmed.contains("://") {
            guard let host = URL(string: trimmed)?.host else { return nil }
            normalized = host.lowercased()
        } else {
            normalized = trimmed.lowercased()
        }
        while normalized.hasSuffix(".") { normalized.removeLast() }
        guard !normalized.isEmpty,
              normalized.utf8.count <= maximumMetadataBytes,
              !normalized.contains("/"),
              !normalized.contains(":"),
              normalized.rangeOfCharacter(from: .whitespacesAndNewlines) == nil else {
            return nil
        }
        return normalized
    }

    /// Resolve the optional per-cipher key from `enc_cipher_key`. A present-but-unparseable
    /// or undecryptable cipher key is a corrupt row (`.malformed`); the locked invariant
    /// propagates as `.locked`.
    private func resolveCipherKey(_ row: CipherRow) async throws -> SymmetricCryptoKey? {
        guard let wire = row.encCipherKey else { return nil }
        let protected: EncString
        do { protected = try EncString(parsing: wire) }
        catch { throw VaultReaderError.malformed }
        do {
            return try await keyVault.cipherKey(fromProtected: protected)
        } catch KeyVaultError.locked {
            throw VaultReaderError.locked
        } catch {
            throw VaultReaderError.malformed
        }
    }

    /// Decrypt a wire EncString string to UTF-8 text. A locked vault → `.locked`; a
    /// parse/decrypt/encoding failure → `.malformed`.
    private func decryptWire(_ wire: String, cipherKey: SymmetricCryptoKey?) async throws -> String {
        let data = try await decryptWireData(wire, cipherKey: cipherKey)
        guard let s = String(data: data, encoding: .utf8) else { throw VaultReaderError.malformed }
        return s
    }

    /// Decrypt a wire EncString string to raw bytes (e.g. a PKCS#8 key).
    private func decryptWireData(_ wire: String, cipherKey: SymmetricCryptoKey?) async throws -> Data {
        let enc: EncString
        do { enc = try EncString(parsing: wire) }
        catch { throw VaultReaderError.malformed }
        do {
            return try await keyVault.decrypt(enc, cipherKey: cipherKey)
        } catch KeyVaultError.locked {
            throw VaultReaderError.locked
        } catch {
            throw VaultReaderError.malformed
        }
    }

    /// Best-effort decrypt: returns `nil` for a missing field or any failure (used for the
    /// optional fields of `decryptOneCipher`, which must not abort on a single bad field).
    private func optionalDecrypt(_ wire: String?, cipherKey: SymmetricCryptoKey?) async -> String? {
        guard let wire else { return nil }
        return try? await decryptWire(wire, cipherKey: cipherKey)
    }

    /// Find the credential whose decrypted RP id and decoded credential id both exactly
    /// match the assertion request. Never fall back to another credential on the same RP.
    private func matchingCredential(_ credentials: [ReaderBlob.Fido2],
                                    rpId: String,
                                    credentialID: Data,
                                    cipherKey: SymmetricCryptoKey?) async -> ReaderBlob.Fido2? {
        for credential in credentials {
            if let rpWire = credential.rpId,
               let decryptedRP = try? await decryptWire(rpWire, cipherKey: cipherKey),
               Self.normalizedRPID(decryptedRP) == Self.normalizedRPID(rpId),
               let credentialIDWire = credential.credentialId,
               let encodedCredentialID = try? await decryptWire(
                   credentialIDWire,
                   cipherKey: cipherKey
               ),
               Self.decodeCredentialID(encodedCredentialID) == credentialID {
                return credential
            }
        }
        return nil
    }

    /// Decode Bitwarden's FIDO2 credential-id plaintext representation. UUID credentials
    /// are their 16 RFC-4122 bytes; arbitrary ids use `b64.<unpadded base64url>`.
    private static func decodeCredentialID(_ value: String) -> Data? {
        if value.utf8.count == 36, let uuid = UUID(uuidString: value) {
            let bytes = uuid.uuid
            return Data([
                bytes.0, bytes.1, bytes.2, bytes.3,
                bytes.4, bytes.5, bytes.6, bytes.7,
                bytes.8, bytes.9, bytes.10, bytes.11,
                bytes.12, bytes.13, bytes.14, bytes.15,
            ])
        }
        guard value.hasPrefix("b64.") else { return nil }
        return decodeBase64URL(String(value.dropFirst(4)))
    }

    /// Decode an unpadded base64url string without accepting the padded/base64 alphabet.
    private static func decodeBase64URL(_ value: String) -> Data? {
        guard !value.isEmpty else { return nil }
        for byte in value.utf8 {
            let isAlphaNumeric = (byte >= 65 && byte <= 90)
                || (byte >= 97 && byte <= 122)
                || (byte >= 48 && byte <= 57)
            guard isAlphaNumeric || byte == 45 || byte == 95 else { return nil }
        }
        let remainder = value.utf8.count % 4
        guard remainder != 1 else { return nil }
        var base64 = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        if remainder != 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }
        return Data(base64Encoded: base64)
    }

    /// Decrypt the FIDO2 counter (a decimal string) into a `UInt32`. Missing/unparseable
    /// counters default to 0 (a fresh credential).
    private func decodeSignCount(_ wire: String?, cipherKey: SymmetricCryptoKey?) async -> UInt32 {
        guard let wire,
              let text = try? await decryptWire(wire, cipherKey: cipherKey),
              let value = UInt32(text.trimmingCharacters(in: .whitespaces)) else { return 0 }
        return value
    }
}
