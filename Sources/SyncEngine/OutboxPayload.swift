import Foundation
import CryptoCore
import VaultModels
import Networking

/// The JSON payload persisted in an `outbox` row's `payload_json` for a cipher
/// create/update.
///
/// `Networking.CipherRequest` is `Encodable`-only (it's a wire body), so the outbox
/// can't round-trip it directly. This is a pragmatic `Codable` mirror of the fields
/// the M1 write paths need; `cipherRequest(lastKnownRevisionDate:)` reconstitutes a
/// real `CipherRequest` to hand to the API at flush time.
///
/// EncString fields are stored as their wire `stringValue` (a plain `String`), exactly
/// as they go over the wire, so the payload is stable and human-greppable.
public struct OutboxCipherPayload: Codable, Sendable, Equatable {
    public var type: Int
    public var name: String
    public var notes: String?
    public var folderID: String?
    public var organizationID: String?
    public var favorite: Bool
    public var reprompt: Int
    public var key: String?
    public var login: Login?
    public var card: Card?
    public var identity: Identity?
    public var secureNote: SecureNote?
    public var sshKey: SshKey?
    public var fields: [Field]?

    public struct Login: Codable, Sendable, Equatable {
        public var username: String?
        public var password: String?
        public var totp: String?
        public var uris: [Uri]?
        public var fido2Credentials: [Fido2]?
        public var passwordRevisionDate: Date?
        public init(username: String? = nil, password: String? = nil,
                    totp: String? = nil, uris: [Uri]? = nil,
                    fido2Credentials: [Fido2]? = nil,
                    passwordRevisionDate: Date? = nil) {
            self.username = username; self.password = password
            self.totp = totp; self.uris = uris
            self.fido2Credentials = fido2Credentials
            self.passwordRevisionDate = passwordRevisionDate
        }
    }
    public struct Uri: Codable, Sendable, Equatable {
        public var uri: String?
        public var match: Int?
        public init(uri: String? = nil, match: Int? = nil) { self.uri = uri; self.match = match }
    }
    public struct Fido2: Codable, Sendable, Equatable {
        public var credentialId: String?
        public var keyType: String?
        public var keyAlgorithm: String?
        public var keyCurve: String?
        public var keyValue: String?
        public var rpId: String?
        public var rpName: String?
        public var userHandle: String?
        public var userName: String?
        public var userDisplayName: String?
        public var counter: String?
        public var discoverable: String?
        public var creationDate: Date?

        public init(credentialId: String? = nil, keyType: String? = nil,
                    keyAlgorithm: String? = nil, keyCurve: String? = nil,
                    keyValue: String? = nil, rpId: String? = nil, rpName: String? = nil,
                    userHandle: String? = nil, userName: String? = nil,
                    userDisplayName: String? = nil, counter: String? = nil,
                    discoverable: String? = nil, creationDate: Date? = nil) {
            self.credentialId = credentialId; self.keyType = keyType
            self.keyAlgorithm = keyAlgorithm; self.keyCurve = keyCurve
            self.keyValue = keyValue; self.rpId = rpId; self.rpName = rpName
            self.userHandle = userHandle; self.userName = userName
            self.userDisplayName = userDisplayName; self.counter = counter
            self.discoverable = discoverable; self.creationDate = creationDate
        }
    }
    public struct Card: Codable, Sendable, Equatable {
        public var cardholderName: String?
        public var brand: String?
        public var number: String?
        public var expMonth: String?
        public var expYear: String?
        public var code: String?
        public init(cardholderName: String? = nil, brand: String? = nil, number: String? = nil,
                    expMonth: String? = nil, expYear: String? = nil, code: String? = nil) {
            self.cardholderName = cardholderName; self.brand = brand; self.number = number
            self.expMonth = expMonth; self.expYear = expYear; self.code = code
        }
    }
    public struct Identity: Codable, Sendable, Equatable {
        public var title: String?
        public var firstName: String?
        public var middleName: String?
        public var lastName: String?
        public var address1: String?
        public var address2: String?
        public var address3: String?
        public var city: String?
        public var state: String?
        public var postalCode: String?
        public var country: String?
        public var company: String?
        public var email: String?
        public var phone: String?
        public var ssn: String?
        public var username: String?
        public var passportNumber: String?
        public var licenseNumber: String?
        public init(title: String? = nil, firstName: String? = nil,
                    middleName: String? = nil, lastName: String? = nil,
                    address1: String? = nil, address2: String? = nil,
                    address3: String? = nil, city: String? = nil, state: String? = nil,
                    postalCode: String? = nil, country: String? = nil,
                    company: String? = nil, email: String? = nil, phone: String? = nil,
                    ssn: String? = nil, username: String? = nil,
                    passportNumber: String? = nil, licenseNumber: String? = nil) {
            self.title = title; self.firstName = firstName; self.middleName = middleName
            self.lastName = lastName; self.address1 = address1; self.address2 = address2
            self.address3 = address3; self.city = city; self.state = state
            self.postalCode = postalCode; self.country = country; self.company = company
            self.email = email; self.phone = phone; self.ssn = ssn; self.username = username
            self.passportNumber = passportNumber; self.licenseNumber = licenseNumber
        }
    }
    public struct SecureNote: Codable, Sendable, Equatable {
        public var type: Int
        public init(type: Int = 0) { self.type = type }
    }
    public struct SshKey: Codable, Sendable, Equatable {
        public var privateKey: String?
        public var publicKey: String?
        public var keyFingerprint: String?
        public init(privateKey: String? = nil, publicKey: String? = nil,
                    keyFingerprint: String? = nil) {
            self.privateKey = privateKey; self.publicKey = publicKey
            self.keyFingerprint = keyFingerprint
        }
    }
    public struct Field: Codable, Sendable, Equatable {
        public var type: Int
        public var name: String?
        public var value: String?
        public var linkedId: Int?
        public init(type: Int, name: String? = nil, value: String? = nil,
                    linkedId: Int? = nil) {
            self.type = type; self.name = name; self.value = value; self.linkedId = linkedId
        }
    }

    public init(type: Int, name: String, notes: String? = nil, folderID: String? = nil,
                organizationID: String? = nil, favorite: Bool = false, reprompt: Int = 0,
                key: String? = nil, login: Login? = nil, card: Card? = nil,
                identity: Identity? = nil, secureNote: SecureNote? = nil,
                sshKey: SshKey? = nil, fields: [Field]? = nil) {
        self.type = type
        self.name = name
        self.notes = notes
        self.folderID = folderID
        self.organizationID = organizationID
        self.favorite = favorite
        self.reprompt = reprompt
        self.key = key
        self.login = login
        self.card = card
        self.identity = identity
        self.secureNote = secureNote
        self.sshKey = sshKey
        self.fields = fields
    }

    /// JSON-encode for storage in `outbox.payload_json`.
    public func encodedJSON() throws -> String {
        let data = try JSONEncoder().encode(self)
        return String(decoding: data, as: UTF8.self)
    }

    /// Decode from a stored `outbox.payload_json` string.
    public static func decode(_ json: String) throws -> OutboxCipherPayload {
        try JSONDecoder().decode(OutboxCipherPayload.self, from: Data(json.utf8))
    }

    /// Rebuild a `Networking.CipherRequest` for the API, stamping the optimistic-
    /// concurrency token. Wire EncString strings are reparsed back into `EncString`;
    /// a malformed stored string throws (treated as a hard error by the caller).
    public func cipherRequest(lastKnownRevisionDate: Date?) throws -> CipherRequest {
        func enc(_ s: String?) throws -> EncString? {
            guard let s else { return nil }
            return try EncString(parsing: s)
        }

        let loginReq: CipherLoginRequest? = try login.map { l in
            CipherLoginRequest(
                username: try enc(l.username),
                password: try enc(l.password),
                totp: try enc(l.totp),
                uris: try l.uris?.map { CipherLoginUriRequest(uri: try enc($0.uri), match: $0.match) },
                fido2Credentials: try l.fido2Credentials?.map { f in
                    CipherFido2CredentialRequest(
                        credentialId: try enc(f.credentialId),
                        keyType: try enc(f.keyType),
                        keyAlgorithm: try enc(f.keyAlgorithm),
                        keyCurve: try enc(f.keyCurve),
                        keyValue: try enc(f.keyValue),
                        rpId: try enc(f.rpId),
                        rpName: try enc(f.rpName),
                        userHandle: try enc(f.userHandle),
                        userName: try enc(f.userName),
                        userDisplayName: try enc(f.userDisplayName),
                        counter: try enc(f.counter),
                        discoverable: try enc(f.discoverable),
                        creationDate: f.creationDate
                    )
                },
                passwordRevisionDate: l.passwordRevisionDate
            )
        }
        let cardReq: CipherCardRequest? = try card.map { c in
            CipherCardRequest(
                cardholderName: try enc(c.cardholderName),
                brand: try enc(c.brand),
                number: try enc(c.number),
                expMonth: try enc(c.expMonth),
                expYear: try enc(c.expYear),
                code: try enc(c.code)
            )
        }
        let identityReq: CipherIdentityRequest? = try identity.map { i in
            CipherIdentityRequest(
                title: try enc(i.title),
                firstName: try enc(i.firstName),
                middleName: try enc(i.middleName),
                lastName: try enc(i.lastName),
                address1: try enc(i.address1),
                address2: try enc(i.address2),
                address3: try enc(i.address3),
                city: try enc(i.city),
                state: try enc(i.state),
                postalCode: try enc(i.postalCode),
                country: try enc(i.country),
                company: try enc(i.company),
                email: try enc(i.email),
                phone: try enc(i.phone),
                ssn: try enc(i.ssn),
                username: try enc(i.username),
                passportNumber: try enc(i.passportNumber),
                licenseNumber: try enc(i.licenseNumber)
            )
        }
        let secureNoteReq: CipherSecureNoteRequest? = secureNote.map {
            CipherSecureNoteRequest(type: $0.type)
        }
        let sshKeyReq: CipherSshKeyRequest? = try sshKey.map { s in
            CipherSshKeyRequest(privateKey: try enc(s.privateKey),
                                publicKey: try enc(s.publicKey),
                                keyFingerprint: try enc(s.keyFingerprint))
        }
        let fieldReqs: [CipherFieldRequest]? = try fields?.map { f in
            CipherFieldRequest(type: f.type, name: try enc(f.name), value: try enc(f.value),
                               linkedId: f.linkedId)
        }

        // `name` is required: parse its wire string directly. A malformed string throws
        // out of `EncString(parsing:)` (a hard error the caller treats as a corrupt row).
        let nameEnc = try EncString(parsing: name)

        return CipherRequest(
            type: type,
            name: nameEnc,
            notes: try enc(notes),
            folderId: folderID,
            organizationId: organizationID,
            favorite: favorite,
            reprompt: reprompt,
            key: try enc(key),
            login: loginReq,
            card: cardReq,
            identity: identityReq,
            secureNote: secureNoteReq,
            sshKey: sshKeyReq,
            fields: fieldReqs,
            lastKnownRevisionDate: lastKnownRevisionDate
        )
    }
}

/// The set of outbox operation types `SyncEngine` understands.
public enum OutboxOp: String, Sendable {
    case create
    case update
    case delete
}

/// The entity types `SyncEngine` flushes. M1 handles ciphers; folders are routed
/// through the same machinery in a later milestone.
public enum OutboxEntity: String, Sendable {
    case cipher
}
