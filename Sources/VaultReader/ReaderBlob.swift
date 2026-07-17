import Foundation

/// The `enc_blob` payload as `VaultReader` reads it: the cipher's login sub-payload of
/// EncString **wire strings** (plain `String`s), decoded just enough to vend a single
/// credential or build a passkey assertion. Decryption happens in `VaultReader`, never
/// here.
///
/// This mirrors the blob `SyncEngine` writes (a JSON object of wire strings) but decodes a
/// SUPERSET of the FIDO2 fields: the assertion path needs `keyValue` (base64url PKCS#8)
/// and `counter`, which the AutoFill-identity index doesn't carry. Decoding is keyed,
/// so fields the writer omitted simply decode to `nil` — forward/backward compatible.
struct ReaderBlob: Decodable, Sendable {
    var login: Login?

    struct Login: Decodable, Sendable {
        var username: String?
        var password: String?
        var totp: String?
        var uris: [Uri]?
        var fido2Credentials: [Fido2]?
    }

    struct Uri: Decodable, Sendable {
        var uri: String?
        var match: Int?
    }

    /// A FIDO2 credential's stored wire strings. `keyValue` is the EncString wrapping the
    /// unpadded-base64url PKCS#8 DER; `counter` wraps the decimal sign count.
    struct Fido2: Decodable, Sendable {
        var credentialId: String?
        var keyType: String?
        var keyAlgorithm: String?
        var keyCurve: String?
        var keyValue: String?
        var rpId: String?
        var userHandle: String?
        var userName: String?
        var counter: String?
        var discoverable: String?
    }

    /// Parse a stored `enc_blob` JSON string. Returns `nil` on absent/malformed JSON so
    /// callers can map to the appropriate `VaultReaderError`.
    static func parse(_ blob: String?) -> ReaderBlob? {
        guard let blob, let data = blob.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(ReaderBlob.self, from: data)
    }
}
