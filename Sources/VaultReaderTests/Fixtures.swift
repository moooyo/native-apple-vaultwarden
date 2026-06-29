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
    static func loginRow(id: String, name: String, username: String, password: String,
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

    /// Build a passkey `CipherRow`: a login whose `enc_blob` carries one FIDO2 credential
    /// with the given PKCS#8 private key, rpId, and counter — all encrypted under the user
    /// key. Returns the row.
    static func passkeyRow(id: String, name: String, rpId: String, userName: String,
                           pkcs8: Data, counter: UInt32 = 0) -> CipherRow {
        let blob = """
        {"login":{"username":null,"password":null,"totp":null,"uris":[],
          "fido2Credentials":[{
            "credentialId":"\(enc("cred-\(id)"))",
            "keyType":"\(enc("public-key"))",
            "keyAlgorithm":"\(enc("ECDSA"))",
            "keyCurve":"\(enc("P-256"))",
            "keyValue":"\(encData(pkcs8))",
            "rpId":"\(enc(rpId))",
            "userHandle":"\(enc("handle-\(id)"))",
            "userName":"\(enc(userName))",
            "counter":"\(enc(String(counter)))",
            "discoverable":"\(enc("true"))"
          }]}}
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
