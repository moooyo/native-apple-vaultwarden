import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import SyncEngine
import Fido2

/// Test fixtures: a real `KeyVault` unlocked with a synthetic 64-byte user key,
/// EncString values encrypted under that key, and JSON `SyncResponse` payloads that
/// decode (via `VaultJSON.decoder()`) into real models the engine can decrypt.
enum Fixtures {
    static let accountID = "user-1"

    /// A deterministic 64-byte user key (32B enc || 32B mac).
    static func userKeyData() -> Data {
        Data((0..<64).map { UInt8(($0 * 7 + 3) & 0xff) })
    }

    static func userKey() -> SymmetricCryptoKey {
        try! SymmetricCryptoKey(combined: userKeyData())
    }

    /// A `KeyVault` unlocked with the synthetic user key.
    static func unlockedVault() async -> KeyVault {
        let v = KeyVault()
        await v.unlock(userKey: userKey())
        return v
    }

    /// Encrypt a UTF-8 string under the user key, returning the wire EncString string.
    static func enc(_ plaintext: String) -> String {
        let e = try! SymmetricCrypto.encrypt(Data(plaintext.utf8), using: userKey())
        return e.stringValue
    }

    /// A fresh temp-file `VaultStore` (real SQLite, isolated per call).
    static func freshStore() throws -> (VaultStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("syncengine-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("vault.sqlite")
        let store = try VaultStore(databaseURL: url, passphrase: Data("test-passphrase".utf8))
        return (store, dir)
    }

    static func cleanup(_ dir: URL) {
        try? FileManager.default.removeItem(at: dir)
    }

    static func seedAccounts(_ ids: [String], in store: VaultStore) async throws {
        try await store.upsertAccounts(ids.map { AccountRow(id: $0) })
    }

    // MARK: - SyncResponse JSON builders

    /// ISO-8601 string with fractional seconds (matching server precision).
    static func iso(_ date: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.string(from: date)
    }

    /// A login cipher with a name, username, and a single URI (so it yields one
    /// AutoFill identity). `key:null` → fields are encrypted directly under the user key.
    static func loginCipherJSON(id: String, name: String, username: String,
                                uri: String, revision: Date, totp: String? = nil,
                                passwordWire: String? = nil,
                                cipherKeyWire: String? = nil) -> String {
        let totpField = totp.map { "\"\(enc($0))\"" } ?? "null"
        let storedPassword = passwordWire ?? enc("pw-\(id)")
        let storedCipherKey = cipherKeyWire.map { "\"\($0)\"" } ?? "null"
        return """
        {"id":"\(id)","organizationId":null,"folderId":null,"type":1,
         "name":"\(enc(name))","notes":null,"favorite":false,"reprompt":0,
         "edit":true,"viewPassword":true,
         "login":{"username":"\(enc(username))","password":"\(storedPassword)",
            "totp":\(totpField),
            "uris":[{"uri":"\(enc(uri))","match":null}],
            "fido2Credentials":null,"passwordRevisionDate":null},
         "card":null,"identity":null,"secureNote":null,"sshKey":null,
         "fields":null,"attachments":null,"collectionIds":null,"key":\(storedCipherKey),
         "revisionDate":"\(iso(revision))",
         "creationDate":"2026-01-01T00:00:00.000Z","deletedDate":null}
        """
    }

    static func type7CipherJSON(id: String, revision: Date) -> String {
        """
        {"id":"\(id)","organizationId":null,"folderId":null,"type":1,
         "name":"7.AQID","notes":null,"favorite":false,"reprompt":0,
         "edit":true,"viewPassword":true,"login":null,"card":null,
         "identity":null,"secureNote":null,"sshKey":null,"fields":null,
         "attachments":null,"collectionIds":null,"key":null,
         "revisionDate":"\(iso(revision))",
         "creationDate":"2026-01-01T00:00:00.000Z","deletedDate":null}
        """
    }

    static func type1CipherJSON(id: String, revision: Date) -> String {
        """
        {"id":"\(id)","organizationId":null,"folderId":null,"type":1,
         "name":"1.AQ==|Ag==|Aw==","notes":null,"favorite":false,"reprompt":0,
         "edit":true,"viewPassword":true,"login":null,"card":null,
         "identity":null,"secureNote":null,"sshKey":null,"fields":null,
         "attachments":null,"collectionIds":null,"key":null,
         "revisionDate":"\(iso(revision))",
         "creationDate":"2026-01-01T00:00:00.000Z","deletedDate":null}
        """
    }

    struct PasskeyRecord {
        var credentialIDValue: String
        var rpId: String
        var userHandle: Data
        var userName: String
    }

    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// A login with arbitrary URI and FIDO2 counts, used to prove passkeys are indexed
    /// once per credential rather than once per URI.
    static func loginCipherWithPasskeysJSON(
        id: String,
        name: String,
        username: String,
        uris: [String],
        revision: Date,
        totp: String? = nil,
        passkeys: [PasskeyRecord],
        keyValuePlaintext: String? = nil
    ) -> String {
        let totpField = totp.map { "\"\(enc($0))\"" } ?? "null"
        let uriFields = uris.map {
            "{\"uri\":\"\(enc($0))\",\"match\":null}"
        }.joined(separator: ",")
        let passkeyFields = passkeys.map { passkey in
            let keyValue = keyValuePlaintext
                ?? base64URL(CredentialKey().exportPKCS8())
            return """
            {"credentialId":"\(enc(passkey.credentialIDValue))",
             "keyType":"\(enc("public-key"))","keyAlgorithm":"\(enc("ECDSA"))",
             "keyCurve":"\(enc("P-256"))","keyValue":"\(enc(keyValue))",
             "rpId":"\(enc(passkey.rpId))","rpName":null,
             "userHandle":"\(enc(base64URL(passkey.userHandle)))",
             "userName":"\(enc(passkey.userName))","userDisplayName":null,
             "counter":"\(enc("0"))","discoverable":"\(enc("true"))",
             "creationDate":"2026-01-01T00:00:00.000Z"}
            """
        }.joined(separator: ",")
        return """
        {"id":"\(id)","organizationId":null,"folderId":null,"type":1,
         "name":"\(enc(name))","notes":null,"favorite":false,"reprompt":0,
         "edit":true,"viewPassword":true,
         "login":{"username":"\(enc(username))","password":"\(enc("pw-\(id)"))",
            "totp":\(totpField),"uris":[\(uriFields)],
            "fido2Credentials":[\(passkeyFields)],"passwordRevisionDate":null},
         "card":null,"identity":null,"secureNote":null,"sshKey":null,
         "fields":null,"attachments":null,"collectionIds":null,"key":null,
         "revisionDate":"\(iso(revision))",
         "creationDate":"2026-01-01T00:00:00.000Z","deletedDate":null}
        """
    }

    /// Wrap a list of cipher JSON objects + folders into a full sync payload.
    /// `extraBadCipher` injects a deliberately-malformed cipher (bad EncString name)
    /// to exercise the soft-fail / droppedCipherErrors path.
    static func syncJSON(ciphers: [String], folders: [String] = [], badCipher: Bool = false) -> String {
        var cipherEntries = ciphers
        if badCipher {
            // `name` is "9.foo" — type 9 is not a valid EncryptionType, so EncString
            // parsing throws and the element is dropped into droppedCipherErrors.
            cipherEntries.append("""
            {"id":"bad-1","organizationId":null,"folderId":null,"type":1,
             "name":"9.not-a-valid-encstring","notes":null,"favorite":false,"reprompt":0,
             "edit":true,"viewPassword":true,"login":null,"card":null,"identity":null,
             "secureNote":null,"sshKey":null,"fields":null,"attachments":null,
             "collectionIds":null,"key":null,"revisionDate":"2026-01-02T03:04:05.123Z",
             "creationDate":"2026-01-01T00:00:00.000Z","deletedDate":null}
            """)
        }
        return """
        {"profile":{"id":"\(accountID)","email":"throwaway@example.test","name":"Test User",
          "key":"\(enc("user-key-placeholder"))","privateKey":"\(enc("private-key-placeholder"))",
          "securityStamp":"stamp-1","organizations":[]},
         "folders":[\(folders.joined(separator: ","))],
         "ciphers":[\(cipherEntries.joined(separator: ","))],
         "collections":[],"sends":[],"policies":[],"domains":null}
        """
    }

    static func folderJSON(id: String, name: String, revision: Date) -> String {
        """
        {"id":"\(id)","name":"\(enc(name))","revisionDate":"\(iso(revision))"}
        """
    }

    /// Decode a JSON string into a real `SyncResponse` via the case-insensitive decoder.
    static func decodeSync(_ json: String) -> SyncResponse {
        try! VaultJSON.decoder().decode(SyncResponse.self, from: Data(json.utf8))
    }
}
