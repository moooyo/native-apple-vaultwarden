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

    public struct Login: Codable, Sendable, Equatable {
        public var username: String?
        public var password: String?
        public var totp: String?
        public var uris: [Uri]?
        public init(username: String? = nil, password: String? = nil,
                    totp: String? = nil, uris: [Uri]? = nil) {
            self.username = username; self.password = password
            self.totp = totp; self.uris = uris
        }
    }
    public struct Uri: Codable, Sendable, Equatable {
        public var uri: String?
        public var match: Int?
        public init(uri: String? = nil, match: Int? = nil) { self.uri = uri; self.match = match }
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
        public var firstName: String?
        public var lastName: String?
        public var email: String?
        public var username: String?
        public init(firstName: String? = nil, lastName: String? = nil,
                    email: String? = nil, username: String? = nil) {
            self.firstName = firstName; self.lastName = lastName
            self.email = email; self.username = username
        }
    }
    public struct SecureNote: Codable, Sendable, Equatable {
        public var type: Int
        public init(type: Int = 0) { self.type = type }
    }

    public init(type: Int, name: String, notes: String? = nil, folderID: String? = nil,
                organizationID: String? = nil, favorite: Bool = false, reprompt: Int = 0,
                key: String? = nil, login: Login? = nil, card: Card? = nil,
                identity: Identity? = nil, secureNote: SecureNote? = nil) {
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
                uris: try l.uris?.map { CipherLoginUriRequest(uri: try enc($0.uri), match: $0.match) }
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
                firstName: try enc(i.firstName),
                lastName: try enc(i.lastName),
                email: try enc(i.email),
                username: try enc(i.username)
            )
        }
        let secureNoteReq: CipherSecureNoteRequest? = secureNote.map {
            CipherSecureNoteRequest(type: $0.type)
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
            fields: nil,
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
