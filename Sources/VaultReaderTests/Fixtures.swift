import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import Fido2

/// Test fixtures for `VaultReader`: a real `KeyVault` unlocked with a synthetic 64-byte
/// user key, EncString values encrypted under that key (or under a per-cipher key), a
/// temp-file `VaultStore`, and `CipherRow` builders for login + passkey ciphers whose
/// `enc_blob` mirrors what production stores.
enum Fixtures {
    static let accountID = "user-1"

    /// A deterministic 64-byte user key (32B enc || 32B mac).
    static func userKeyData() -> Data {
        Data((0..<64).map { UInt8(($0 * 7 + 3) & 0xff) })
    }

    static func userKey() -> SymmetricCryptoKey {
        try! SymmetricCryptoKey(combined: userKeyData())
    }

    /// A second deterministic 64-byte key used as a per-cipher key (distinct from the user key).
    static func cipherKeyData() -> Data {
        Data((0..<64).map { UInt8(($0 * 11 + 5) & 0xff) })
    }

    static func cipherKey() -> SymmetricCryptoKey {
        try! SymmetricCryptoKey(combined: cipherKeyData())
    }

    /// A `KeyVault` unlocked with the synthetic user key.
    static func unlockedVault() async -> KeyVault {
        let v = KeyVault()
        await v.unlock(userKey: userKey())
        return v
    }

    /// A locked `KeyVault` (no key).
    static func lockedVault() -> KeyVault { KeyVault() }

    /// Encrypt a UTF-8 string under a key (default: the user key), returning the wire string.
    static func enc(_ plaintext: String, key: SymmetricCryptoKey? = nil) -> String {
        let e = try! SymmetricCrypto.encrypt(Data(plaintext.utf8), using: key ?? userKey())
        return e.stringValue
    }

    /// Encrypt raw bytes under a key (default: user key), returning the wire string.
    static func encData(_ data: Data, key: SymmetricCryptoKey? = nil) -> String {
        let e = try! SymmetricCrypto.encrypt(data, using: key ?? userKey())
        return e.stringValue
    }

    /// The wire string for a per-cipher key wrapped under the user key (a type-2 EncString
    /// of the 64-byte combined key) — this is exactly what `enc_cipher_key` stores.
    static func wrappedCipherKey() -> String {
        encData(cipherKeyData())
    }

    /// A fresh temp-file `VaultStore` (real SQLite, isolated per call), with the account row
    /// pre-inserted (ciphers FK-reference it).
    static func freshStore() async throws -> (VaultStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("vaultreader-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("vault.sqlite")
        let store = try VaultStore(databaseURL: url, passphrase: Data("test-passphrase".utf8))
        try await store.upsertAccounts([AccountRow(id: accountID, email: "throwaway@example.test")])
        return (store, dir)
    }

    static func cleanup(_ dir: URL) {
        try? FileManager.default.removeItem(at: dir)
    }

    static func iso(_ date: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.string(from: date)
    }

    // MARK: - Cipher row builders

    /// Build the `enc_blob` JSON for a login (object of EncString wire strings).
    static func loginBlobJSON(username: String?, password: String?, totp: String? = nil,
                              uris: [String] = [], key: SymmetricCryptoKey? = nil) -> String {
        func field(_ s: String?) -> String { s.map { "\"\(enc($0, key: key))\"" } ?? "null" }
        let uriItems = uris.map { "{\"uri\":\"\(enc($0, key: key))\",\"match\":null}" }
            .joined(separator: ",")
        return """
        {"login":{"username":\(field(username)),"password":\(field(password)),
          "totp":\(totp.map { "\"\(enc($0, key: key))\"" } ?? "null"),
          "uris":[\(uriItems)],"fido2Credentials":null}}
        """
    }

    /// A login `CipherRow` encrypted directly under the user key (no per-cipher key).
    static func loginRow(id: String, accountID: String = Fixtures.accountID,
                         name: String, username: String, password: String,
                         totp: String? = nil, uris: [String] = []) -> CipherRow {
        CipherRow(
            id: id,
            accountID: accountID,
            type: CipherType.login.rawValue,
            revisionDate: iso(Date()),
            creationDate: iso(Date()),
            encName: enc(name),
            encBlob: loginBlobJSON(username: username, password: password, totp: totp, uris: uris),
            encCipherKey: nil,
            searchText: name.lowercased()
        )
    }

    /// A login `CipherRow` whose fields are encrypted under a per-cipher key (which is
    /// itself wrapped under the user key in `enc_cipher_key`).
    static func loginRowWithCipherKey(id: String, name: String, username: String,
                                      password: String) -> CipherRow {
        let ck = cipherKey()
        return CipherRow(
            id: id,
            accountID: accountID,
            type: CipherType.login.rawValue,
            revisionDate: iso(Date()),
            creationDate: iso(Date()),
            encName: enc(name, key: ck),
            encBlob: loginBlobJSON(username: username, password: password, key: ck),
            encCipherKey: wrappedCipherKey(),
            searchText: name.lowercased()
        )
    }

    struct PasskeyRecord {
        var credentialIDValue: String
        var rpId: String
        var userName: String
        var userHandle: Data
        var pkcs8: Data
        var counter: UInt32 = 0
        var storesLegacyRawKeyValue = false
    }

    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func passkeyCredentialID(for id: String) -> Data {
        Data("cred-\(id)".utf8)
    }

    /// Build a passkey `CipherRow` using Bitwarden's official plaintext encodings:
    /// arbitrary credential ids use `b64.` + base64url, user handles use base64url, and
    /// PKCS#8 `keyValue` is base64url before field encryption.
    static func passkeyRow(id: String, name: String, rpId: String, userName: String,
                           pkcs8: Data, counter: UInt32 = 0) -> CipherRow {
        let credentialID = passkeyCredentialID(for: id)
        return passkeyRow(
            id: id,
            name: name,
            credentials: [PasskeyRecord(
                credentialIDValue: "b64.\(base64URL(credentialID))",
                rpId: rpId,
                userName: userName,
                userHandle: Data("handle-\(id)".utf8),
                pkcs8: pkcs8,
                counter: counter
            )]
        )
    }

    /// Build a login containing multiple FIDO2 credentials. This exercises exact
    /// credential selection when several keys belong to the same relying party.
    static func passkeyRow(id: String, name: String,
                           credentials: [PasskeyRecord]) -> CipherRow {
        let credentialItems = credentials.map { credential in
            let keyValue = credential.storesLegacyRawKeyValue
                ? encData(credential.pkcs8)
                : enc(base64URL(credential.pkcs8))
            return """
            {
              "credentialId":"\(enc(credential.credentialIDValue))",
              "keyType":"\(enc("public-key"))",
              "keyAlgorithm":"\(enc("ECDSA"))",
              "keyCurve":"\(enc("P-256"))",
              "keyValue":"\(keyValue)",
              "rpId":"\(enc(credential.rpId))",
              "userHandle":"\(enc(base64URL(credential.userHandle)))",
              "userName":"\(enc(credential.userName))",
              "counter":"\(enc(String(credential.counter)))",
              "discoverable":"\(enc("true"))"
            }
            """
        }.joined(separator: ",")
        let blob = """
        {"login":{"username":null,"password":null,"totp":null,"uris":[],
          "fido2Credentials":[\(credentialItems)]}}
        """
        return CipherRow(
            id: id,
            accountID: accountID,
            type: CipherType.login.rawValue,
            revisionDate: iso(Date()),
            creationDate: iso(Date()),
            encName: enc(name),
            encBlob: blob,
            encCipherKey: nil,
            searchText: name.lowercased()
        )
    }

    /// A non-login (secure note) row: a name but no login blob.
    static func secureNoteRow(id: String, name: String) -> CipherRow {
        CipherRow(
            id: id,
            accountID: accountID,
            type: CipherType.secureNote.rawValue,
            revisionDate: iso(Date()),
            creationDate: iso(Date()),
            encName: enc(name),
            encBlob: "{\"secureNote\":{\"type\":0}}",
            encCipherKey: nil,
            searchText: name.lowercased()
        )
    }
}
