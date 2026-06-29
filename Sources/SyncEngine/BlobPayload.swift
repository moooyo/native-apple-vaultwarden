import Foundation
import CryptoCore
import VaultModels

/// The `enc_blob` payload: the cipher's type sub-payloads serialized as JSON of
/// EncString **wire strings** (plain `String`s). Decryption happens later, in the
/// repository / `VaultReader`. Storing wire strings (not nested EncString objects)
/// keeps the blob compact and re-parsable.
struct BlobPayload: Codable, Sendable, Equatable {
    var login: Login?
    var card: Card?
    var identity: Identity?
    var secureNote: SecureNote?
    var sshKey: SshKey?
    var fields: [Field]?

    struct Login: Codable, Sendable, Equatable {
        var username: String?
        var password: String?
        var totp: String?
        var uris: [Uri]?
        var fido2Credentials: [Fido2]?
    }
    struct Uri: Codable, Sendable, Equatable {
        var uri: String?
        var match: Int?
    }
    struct Fido2: Codable, Sendable, Equatable {
        var credentialId: String?
        var rpId: String?
        var userName: String?
    }
    struct Card: Codable, Sendable, Equatable {
        var cardholderName: String?
        var brand: String?
        var number: String?
        var expMonth: String?
        var expYear: String?
        var code: String?
    }
    struct Identity: Codable, Sendable, Equatable {
        var firstName: String?
        var lastName: String?
        var email: String?
        var username: String?
        var phone: String?
    }
    struct SecureNote: Codable, Sendable, Equatable {
        var type: Int
    }
    struct SshKey: Codable, Sendable, Equatable {
        var privateKey: String?
        var publicKey: String?
        var keyFingerprint: String?
    }
    struct Field: Codable, Sendable, Equatable {
        var name: String?
        var value: String?
    }

    /// Build from a server cipher, capturing the EncString wire strings of each field.
    init(_ cipher: CipherResponse) {
        if let l = cipher.login {
            login = Login(
                username: l.username?.stringValue,
                password: l.password?.stringValue,
                totp: l.totp?.stringValue,
                uris: l.uris?.map { Uri(uri: $0.uri?.stringValue, match: $0.match?.rawValue) },
                fido2Credentials: l.fido2Credentials?.map {
                    Fido2(credentialId: $0.credentialId?.stringValue,
                          rpId: $0.rpId?.stringValue,
                          userName: $0.userName?.stringValue)
                }
            )
        }
        if let c = cipher.card {
            card = Card(
                cardholderName: c.cardholderName?.stringValue,
                brand: c.brand?.stringValue,
                number: c.number?.stringValue,
                expMonth: c.expMonth?.stringValue,
                expYear: c.expYear?.stringValue,
                code: c.code?.stringValue
            )
        }
        if let i = cipher.identity {
            identity = Identity(
                firstName: i.firstName?.stringValue,
                lastName: i.lastName?.stringValue,
                email: i.email?.stringValue,
                username: i.username?.stringValue,
                phone: i.phone?.stringValue
            )
        }
        if let n = cipher.secureNote {
            secureNote = SecureNote(type: n.type.rawValue)
        }
        if let s = cipher.sshKey {
            sshKey = SshKey(
                privateKey: s.privateKey?.stringValue,
                publicKey: s.publicKey?.stringValue,
                keyFingerprint: s.keyFingerprint?.stringValue
            )
        }
        if let f = cipher.fields {
            fields = f.map { Field(name: $0.name?.stringValue, value: $0.value?.stringValue) }
        }
    }
}
