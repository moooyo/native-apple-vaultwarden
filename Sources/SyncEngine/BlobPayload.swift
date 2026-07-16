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
        var passwordRevisionDate: Date?
    }
    struct Uri: Codable, Sendable, Equatable {
        var uri: String?
        var match: Int?
    }
    struct Fido2: Codable, Sendable, Equatable {
        var credentialId: String?
        var keyType: String?
        var keyAlgorithm: String?
        var keyCurve: String?
        var keyValue: String?
        var rpId: String?
        var rpName: String?
        var userHandle: String?
        var userName: String?
        var userDisplayName: String?
        var counter: String?
        var discoverable: String?
        var creationDate: Date?
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
        var title: String?
        var firstName: String?
        var middleName: String?
        var lastName: String?
        var address1: String?
        var address2: String?
        var address3: String?
        var city: String?
        var state: String?
        var postalCode: String?
        var country: String?
        var company: String?
        var email: String?
        var phone: String?
        var ssn: String?
        var username: String?
        var passportNumber: String?
        var licenseNumber: String?
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
        var type: Int?
        var name: String?
        var value: String?
        var linkedId: Int?
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
                          keyType: $0.keyType?.stringValue,
                          keyAlgorithm: $0.keyAlgorithm?.stringValue,
                          keyCurve: $0.keyCurve?.stringValue,
                          keyValue: $0.keyValue?.stringValue,
                          rpId: $0.rpId?.stringValue,
                          rpName: $0.rpName?.stringValue,
                          userHandle: $0.userHandle?.stringValue,
                          userName: $0.userName?.stringValue,
                          userDisplayName: $0.userDisplayName?.stringValue,
                          counter: $0.counter?.stringValue,
                          discoverable: $0.discoverable?.stringValue,
                          creationDate: $0.creationDate)
                },
                passwordRevisionDate: l.passwordRevisionDate
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
                title: i.title?.stringValue,
                firstName: i.firstName?.stringValue,
                middleName: i.middleName?.stringValue,
                lastName: i.lastName?.stringValue,
                address1: i.address1?.stringValue,
                address2: i.address2?.stringValue,
                address3: i.address3?.stringValue,
                city: i.city?.stringValue,
                state: i.state?.stringValue,
                postalCode: i.postalCode?.stringValue,
                country: i.country?.stringValue,
                company: i.company?.stringValue,
                email: i.email?.stringValue,
                phone: i.phone?.stringValue,
                ssn: i.ssn?.stringValue,
                username: i.username?.stringValue,
                passportNumber: i.passportNumber?.stringValue,
                licenseNumber: i.licenseNumber?.stringValue
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
            fields = f.map {
                Field(type: $0.type.rawValue, name: $0.name?.stringValue,
                      value: $0.value?.stringValue, linkedId: $0.linkedId)
            }
        }
    }
}
