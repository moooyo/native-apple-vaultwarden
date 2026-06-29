import Foundation
import CryptoCore

// MARK: - Cipher

/// Request body for cipher create/update (`POST/PUT /api/ciphers`).
///
/// Mirrors Bitwarden's `CipherRequestModel`. EncString-typed fields are encoded as
/// their wire `stringValue` so the server receives the exact `type.iv|ct|mac`
/// strings. The vault sub-payloads (`login`, `card`, …) are reused from VaultModels
/// where they already round-trip; only the cipher-level envelope differs from
/// `CipherResponse` (no server-assigned `id`/dates; adds `lastKnownRevisionDate`).
public struct CipherRequest: Encodable, Sendable {
    public var type: Int
    public var name: EncString
    public var notes: EncString?
    public var folderId: String?
    public var organizationId: String?
    public var favorite: Bool
    public var reprompt: Int
    public var key: EncString?
    public var login: CipherLoginRequest?
    public var card: CipherCardRequest?
    public var identity: CipherIdentityRequest?
    public var secureNote: CipherSecureNoteRequest?
    public var fields: [CipherFieldRequest]?
    /// Optimistic-concurrency token: the `revisionDate` the client last saw for this
    /// cipher. The server rejects the write with 400 if it has a newer revision.
    public var lastKnownRevisionDate: Date?

    public init(type: Int, name: EncString, notes: EncString? = nil, folderId: String? = nil,
                organizationId: String? = nil, favorite: Bool = false, reprompt: Int = 0,
                key: EncString? = nil, login: CipherLoginRequest? = nil,
                card: CipherCardRequest? = nil, identity: CipherIdentityRequest? = nil,
                secureNote: CipherSecureNoteRequest? = nil, fields: [CipherFieldRequest]? = nil,
                lastKnownRevisionDate: Date? = nil) {
        self.type = type
        self.name = name
        self.notes = notes
        self.folderId = folderId
        self.organizationId = organizationId
        self.favorite = favorite
        self.reprompt = reprompt
        self.key = key
        self.login = login
        self.card = card
        self.identity = identity
        self.secureNote = secureNote
        self.fields = fields
        self.lastKnownRevisionDate = lastKnownRevisionDate
    }

    enum CodingKeys: String, CodingKey {
        case type, name, notes, folderId, organizationId, favorite, reprompt, key
        case login, card, identity, secureNote, fields, lastKnownRevisionDate
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(type, forKey: .type)
        try c.encodeEncString(name, forKey: .name)
        try c.encodeEncStringIfPresent(notes, forKey: .notes)
        try c.encodeIfPresent(folderId, forKey: .folderId)
        try c.encodeIfPresent(organizationId, forKey: .organizationId)
        try c.encode(favorite, forKey: .favorite)
        try c.encode(reprompt, forKey: .reprompt)
        try c.encodeEncStringIfPresent(key, forKey: .key)
        try c.encodeIfPresent(login, forKey: .login)
        try c.encodeIfPresent(card, forKey: .card)
        try c.encodeIfPresent(identity, forKey: .identity)
        try c.encodeIfPresent(secureNote, forKey: .secureNote)
        try c.encodeIfPresent(fields, forKey: .fields)
        try c.encodeIfPresent(lastKnownRevisionDate, forKey: .lastKnownRevisionDate)
    }
}

/// Login sub-payload for `CipherRequest`.
public struct CipherLoginRequest: Encodable, Sendable {
    public var username: EncString?
    public var password: EncString?
    public var totp: EncString?
    public var uris: [CipherLoginUriRequest]?

    public init(username: EncString? = nil, password: EncString? = nil,
                totp: EncString? = nil, uris: [CipherLoginUriRequest]? = nil) {
        self.username = username
        self.password = password
        self.totp = totp
        self.uris = uris
    }

    enum CodingKeys: String, CodingKey { case username, password, totp, uris }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeEncStringIfPresent(username, forKey: .username)
        try c.encodeEncStringIfPresent(password, forKey: .password)
        try c.encodeEncStringIfPresent(totp, forKey: .totp)
        try c.encodeIfPresent(uris, forKey: .uris)
    }
}

/// A single login URI in a `CipherLoginRequest`. `match` is the plaintext
/// `UriMatchType` raw value (or `nil` for the default strategy).
public struct CipherLoginUriRequest: Encodable, Sendable {
    public var uri: EncString?
    public var match: Int?

    public init(uri: EncString? = nil, match: Int? = nil) {
        self.uri = uri
        self.match = match
    }

    enum CodingKeys: String, CodingKey { case uri, match }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeEncStringIfPresent(uri, forKey: .uri)
        try c.encodeIfPresent(match, forKey: .match)
    }
}

/// Card sub-payload for `CipherRequest`. All fields are EncString.
public struct CipherCardRequest: Encodable, Sendable {
    public var cardholderName: EncString?
    public var brand: EncString?
    public var number: EncString?
    public var expMonth: EncString?
    public var expYear: EncString?
    public var code: EncString?

    public init(cardholderName: EncString? = nil, brand: EncString? = nil, number: EncString? = nil,
                expMonth: EncString? = nil, expYear: EncString? = nil, code: EncString? = nil) {
        self.cardholderName = cardholderName
        self.brand = brand
        self.number = number
        self.expMonth = expMonth
        self.expYear = expYear
        self.code = code
    }

    enum CodingKeys: String, CodingKey {
        case cardholderName, brand, number, expMonth, expYear, code
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeEncStringIfPresent(cardholderName, forKey: .cardholderName)
        try c.encodeEncStringIfPresent(brand, forKey: .brand)
        try c.encodeEncStringIfPresent(number, forKey: .number)
        try c.encodeEncStringIfPresent(expMonth, forKey: .expMonth)
        try c.encodeEncStringIfPresent(expYear, forKey: .expYear)
        try c.encodeEncStringIfPresent(code, forKey: .code)
    }
}

/// Identity sub-payload for `CipherRequest`. All fields are EncString.
public struct CipherIdentityRequest: Encodable, Sendable {
    public var title: EncString?
    public var firstName: EncString?
    public var middleName: EncString?
    public var lastName: EncString?
    public var address1: EncString?
    public var address2: EncString?
    public var address3: EncString?
    public var city: EncString?
    public var state: EncString?
    public var postalCode: EncString?
    public var country: EncString?
    public var company: EncString?
    public var email: EncString?
    public var phone: EncString?
    public var ssn: EncString?
    public var username: EncString?
    public var passportNumber: EncString?
    public var licenseNumber: EncString?

    public init(title: EncString? = nil, firstName: EncString? = nil, middleName: EncString? = nil,
                lastName: EncString? = nil, address1: EncString? = nil, address2: EncString? = nil,
                address3: EncString? = nil, city: EncString? = nil, state: EncString? = nil,
                postalCode: EncString? = nil, country: EncString? = nil, company: EncString? = nil,
                email: EncString? = nil, phone: EncString? = nil, ssn: EncString? = nil,
                username: EncString? = nil, passportNumber: EncString? = nil,
                licenseNumber: EncString? = nil) {
        self.title = title; self.firstName = firstName; self.middleName = middleName
        self.lastName = lastName; self.address1 = address1; self.address2 = address2
        self.address3 = address3; self.city = city; self.state = state
        self.postalCode = postalCode; self.country = country; self.company = company
        self.email = email; self.phone = phone; self.ssn = ssn; self.username = username
        self.passportNumber = passportNumber; self.licenseNumber = licenseNumber
    }

    enum CodingKeys: String, CodingKey {
        case title, firstName, middleName, lastName, address1, address2, address3
        case city, state, postalCode, country, company, email, phone, ssn, username
        case passportNumber, licenseNumber
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeEncStringIfPresent(title, forKey: .title)
        try c.encodeEncStringIfPresent(firstName, forKey: .firstName)
        try c.encodeEncStringIfPresent(middleName, forKey: .middleName)
        try c.encodeEncStringIfPresent(lastName, forKey: .lastName)
        try c.encodeEncStringIfPresent(address1, forKey: .address1)
        try c.encodeEncStringIfPresent(address2, forKey: .address2)
        try c.encodeEncStringIfPresent(address3, forKey: .address3)
        try c.encodeEncStringIfPresent(city, forKey: .city)
        try c.encodeEncStringIfPresent(state, forKey: .state)
        try c.encodeEncStringIfPresent(postalCode, forKey: .postalCode)
        try c.encodeEncStringIfPresent(country, forKey: .country)
        try c.encodeEncStringIfPresent(company, forKey: .company)
        try c.encodeEncStringIfPresent(email, forKey: .email)
        try c.encodeEncStringIfPresent(phone, forKey: .phone)
        try c.encodeEncStringIfPresent(ssn, forKey: .ssn)
        try c.encodeEncStringIfPresent(username, forKey: .username)
        try c.encodeEncStringIfPresent(passportNumber, forKey: .passportNumber)
        try c.encodeEncStringIfPresent(licenseNumber, forKey: .licenseNumber)
    }
}

/// Secure-note sub-payload for `CipherRequest`. `type` is the plaintext
/// `SecureNoteType` raw value (0 = Generic).
public struct CipherSecureNoteRequest: Encodable, Sendable {
    public var type: Int
    public init(type: Int = 0) { self.type = type }
}

/// A custom field on a cipher. `name`/`value` are EncString; `type` is the
/// plaintext field-type raw value (0 = Text, 1 = Hidden, 2 = Boolean, 3 = Linked).
public struct CipherFieldRequest: Encodable, Sendable {
    public var type: Int
    public var name: EncString?
    public var value: EncString?

    public init(type: Int, name: EncString? = nil, value: EncString? = nil) {
        self.type = type
        self.name = name
        self.value = value
    }

    enum CodingKeys: String, CodingKey { case type, name, value }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(type, forKey: .type)
        try c.encodeEncStringIfPresent(name, forKey: .name)
        try c.encodeEncStringIfPresent(value, forKey: .value)
    }
}

// MARK: - Folder

/// Request body for folder create/update (`POST/PUT /api/folders`). `name` is an
/// EncString.
public struct FolderRequest: Encodable, Sendable {
    public var name: EncString

    public init(name: EncString) { self.name = name }

    enum CodingKeys: String, CodingKey { case name }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeEncString(name, forKey: .name)
    }
}

// MARK: - Attachment

/// Request body for attachment-upload step 1 (`POST /api/ciphers/{id}/attachment/v2`).
/// `key` (the per-attachment encryption key, EncString) and `fileName` (EncString)
/// are encrypted client-side; `fileSize` is the plaintext byte count of the
/// encrypted blob.
public struct AttachmentRequest: Encodable, Sendable {
    public var key: EncString
    public var fileName: EncString
    public var fileSize: Int

    public init(key: EncString, fileName: EncString, fileSize: Int) {
        self.key = key
        self.fileName = fileName
        self.fileSize = fileSize
    }

    enum CodingKeys: String, CodingKey { case key, fileName, fileSize }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeEncString(key, forKey: .key)
        try c.encodeEncString(fileName, forKey: .fileName)
        try c.encode(fileSize, forKey: .fileSize)
    }
}

// MARK: - EncString encoding helpers

extension KeyedEncodingContainer {
    /// Encodes an `EncString` as its wire `stringValue`.
    mutating func encodeEncString(_ value: EncString, forKey key: Key) throws {
        try encode(value.stringValue, forKey: key)
    }

    /// Encodes an optional `EncString` as its wire `stringValue`, omitting the key
    /// when `nil`.
    mutating func encodeEncStringIfPresent(_ value: EncString?, forKey key: Key) throws {
        if let value { try encode(value.stringValue, forKey: key) }
    }
}
