import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import KeychainBridge
import Fido2

/// The AutoFill extension's least-privilege read facade (design spec §5.7 / blueprint §F).
///
/// `VaultReader` is the ONLY vault API the extension links against. It deliberately offers
/// NO networking, NO sync, and NO bulk decryption: it can unlock via biometrics, fetch a
/// SINGLE selected cipher from the local store, and decrypt just that one item's fields —
/// enough to vend a password credential or build a passkey assertion. Keeping the surface
/// this small bounds the extension's link graph and its plaintext lifetime (the ~120MB
/// extension memory red line).
///
/// An `actor` so all access is serialized; every decryption goes through the injected
/// `KeyVault`, so raw key bytes never reach this layer.
public actor VaultReader {
    private let store: VaultStore
    private let keyVault: KeyVault
    private let keychain: KeychainBridge

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
        let userKey = try await keychain.unlockWithBiometrics(reason: reason)
        await keyVault.unlock(userKey: userKey)
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

        guard let login = ReaderBlob.parse(row.encBlob)?.login else {
            throw VaultReaderError.noPasswordField
        }
        guard let userWire = login.username, let passWire = login.password else {
            throw VaultReaderError.noPasswordField
        }

        let cipherKey = try await resolveCipherKey(row)
        let user = try await decryptWire(userWire, cipherKey: cipherKey)
        let password = try await decryptWire(passWire, cipherKey: cipherKey)
        return (user, password)
    }

    // MARK: - Passkey assertion

    /// Build a WebAuthn assertion for the FIDO2 credential on cipher `recordID`.
    ///
    /// Decrypts the credential's `keyValue` (PKCS#8 DER private key) and `counter`, imports
    /// a `Fido2.CredentialKey`, and signs `(authenticatorData || clientDataHash)` via
    /// `Fido2Authenticator.assert`. If no matching credential exists for `rpId`, the first
    /// stored credential is used (a single-credential cipher is the common case).
    ///
    /// The returned `signCount` is the stored counter (or 0). Persisting an incremented
    /// counter is a write path owned by the app/sync layer, not this read-only facade.
    ///
    /// - Throws: `.locked`, `.notFound`, `.noPasskey` (no credential / no decryptable
    ///   key), `.malformed` (bad PKCS#8 / counter).
    public func passkeyAssertion(recordID: String,
                                 rpId: String,
                                 clientDataHash: Data,
                                 userVerified: Bool) async throws
        -> (authenticatorData: Data, signature: Data) {
        guard await keyVault.isUnlocked else { throw VaultReaderError.locked }
        let row = try await fetchRow(recordID)

        guard let credentials = ReaderBlob.parse(row.encBlob)?.login?.fido2Credentials,
              !credentials.isEmpty else {
            throw VaultReaderError.noPasskey
        }
        let cipherKey = try await resolveCipherKey(row)

        // Prefer a credential whose decrypted rpId matches the requested one; otherwise
        // fall back to the first credential (single-passkey ciphers are the norm).
        let chosen = await matchingCredential(credentials, rpId: rpId, cipherKey: cipherKey)
            ?? credentials[0]

        guard let keyWire = chosen.keyValue else { throw VaultReaderError.noPasskey }
        let pkcs8: Data
        do {
            pkcs8 = try await decryptWireData(keyWire, cipherKey: cipherKey)
        } catch VaultReaderError.locked {
            throw VaultReaderError.locked
        } catch {
            throw VaultReaderError.malformed
        }

        let credentialKey: CredentialKey
        do { credentialKey = try CredentialKey(pkcs8: pkcs8) }
        catch { throw VaultReaderError.malformed }

        let signCount = await decodeSignCount(chosen.counter, cipherKey: cipherKey)

        do {
            return try Fido2Authenticator.assert(
                rpId: rpId,
                clientDataHash: clientDataHash,
                signCount: signCount,
                userVerified: userVerified,
                key: credentialKey
            )
        } catch {
            throw VaultReaderError.malformed
        }
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

        return DecryptedCipher(
            id: row.id,
            type: row.type,
            name: name,
            username: username,
            password: password,
            totp: totp,
            uris: uris
        )
    }

    // MARK: - Private helpers

    /// Fetch a row from the store, mapping a missing row to `.notFound`.
    private func fetchRow(_ id: String) async throws -> CipherRow {
        guard let row = try await store.cipher(id: id) else { throw VaultReaderError.notFound }
        return row
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

    /// Find the credential whose decrypted `rpId` equals `rpId`, if any.
    private func matchingCredential(_ credentials: [ReaderBlob.Fido2],
                                    rpId: String,
                                    cipherKey: SymmetricCryptoKey?) async -> ReaderBlob.Fido2? {
        for credential in credentials {
            if let wire = credential.rpId,
               let decrypted = try? await decryptWire(wire, cipherKey: cipherKey),
               decrypted == rpId {
                return credential
            }
        }
        return nil
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
