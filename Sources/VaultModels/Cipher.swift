import Foundation
import CryptoCore

/// A vault item. `name` is always present; everything nullable is optional.
/// EncString-typed fields decode straight into `CryptoCore.EncString`.
public struct CipherResponse: Codable, Sendable, Equatable {
    public let id: String
    public let organizationId: String?
    public let folderId: String?
    public let type: CipherType
    public let name: EncString
    public let notes: EncString?
    public let favorite: Bool
    public let reprompt: Int
    public let edit: Bool?
    public let viewPassword: Bool?
    public let login: LoginModel?
    public let card: CardModel?
    public let identity: IdentityModel?
    public let secureNote: SecureNoteModel?
    public let sshKey: SshKeyModel?
    public let fields: [FieldModel]?
    public let attachments: [AttachmentModel]?
    public let collectionIds: [String]?
    public let key: EncString?
    public let revisionDate: Date
    public let creationDate: Date?
    public let deletedDate: Date?

    public init(id: String, organizationId: String?, folderId: String?, type: CipherType,
                name: EncString, notes: EncString?, favorite: Bool, reprompt: Int,
                edit: Bool?, viewPassword: Bool?, login: LoginModel?, card: CardModel?,
                identity: IdentityModel?, secureNote: SecureNoteModel?, sshKey: SshKeyModel?,
                fields: [FieldModel]?, attachments: [AttachmentModel]?, collectionIds: [String]?,
                key: EncString?, revisionDate: Date, creationDate: Date?, deletedDate: Date?) {
        self.id = id
        self.organizationId = organizationId
        self.folderId = folderId
        self.type = type
        self.name = name
        self.notes = notes
        self.favorite = favorite
        self.reprompt = reprompt
        self.edit = edit
        self.viewPassword = viewPassword
        self.login = login
        self.card = card
        self.identity = identity
        self.secureNote = secureNote
        self.sshKey = sshKey
        self.fields = fields
        self.attachments = attachments
        self.collectionIds = collectionIds
        self.key = key
        self.revisionDate = revisionDate
        self.creationDate = creationDate
        self.deletedDate = deletedDate
    }

    enum CodingKeys: String, CodingKey {
        case id
        case organizationId = "organizationid"
        case folderId = "folderid"
        case type
        case name
        case notes
        case favorite
        case reprompt
        case edit
        case viewPassword = "viewpassword"
        case login
        case card
        case identity
        case secureNote = "securenote"
        case sshKey = "sshkey"
        case fields
        case attachments
        case collectionIds = "collectionids"
        case key
        case revisionDate = "revisiondate"
        case creationDate = "creationdate"
        case deletedDate = "deleteddate"
    }
}

/// Card payload. All fields are EncString on the wire.
public struct CardModel: Codable, Sendable, Equatable {
    public let cardholderName: EncString?
    public let brand: EncString?
    public let number: EncString?
    public let expMonth: EncString?
    public let expYear: EncString?
    public let code: EncString?

    public init(cardholderName: EncString?, brand: EncString?, number: EncString?,
                expMonth: EncString?, expYear: EncString?, code: EncString?) {
        self.cardholderName = cardholderName
        self.brand = brand
        self.number = number
        self.expMonth = expMonth
        self.expYear = expYear
        self.code = code
    }

    enum CodingKeys: String, CodingKey {
        case cardholderName = "cardholdername"
        case brand
        case number
        case expMonth = "expmonth"
        case expYear = "expyear"
        case code
    }
}

/// Identity payload. All fields are EncString on the wire.
public struct IdentityModel: Codable, Sendable, Equatable {
    public let title: EncString?
    public let firstName: EncString?
    public let middleName: EncString?
    public let lastName: EncString?
    public let address1: EncString?
    public let address2: EncString?
    public let address3: EncString?
    public let city: EncString?
    public let state: EncString?
    public let postalCode: EncString?
    public let country: EncString?
    public let company: EncString?
    public let email: EncString?
    public let phone: EncString?
    public let ssn: EncString?
    public let username: EncString?
    public let passportNumber: EncString?
    public let licenseNumber: EncString?

    public init(title: EncString?, firstName: EncString?, middleName: EncString?,
                lastName: EncString?, address1: EncString?, address2: EncString?,
                address3: EncString?, city: EncString?, state: EncString?,
                postalCode: EncString?, country: EncString?, company: EncString?,
                email: EncString?, phone: EncString?, ssn: EncString?, username: EncString?,
                passportNumber: EncString?, licenseNumber: EncString?) {
        self.title = title
        self.firstName = firstName
        self.middleName = middleName
        self.lastName = lastName
        self.address1 = address1
        self.address2 = address2
        self.address3 = address3
        self.city = city
        self.state = state
        self.postalCode = postalCode
        self.country = country
        self.company = company
        self.email = email
        self.phone = phone
        self.ssn = ssn
        self.username = username
        self.passportNumber = passportNumber
        self.licenseNumber = licenseNumber
    }

    enum CodingKeys: String, CodingKey {
        case title
        case firstName = "firstname"
        case middleName = "middlename"
        case lastName = "lastname"
        case address1
        case address2
        case address3
        case city
        case state
        case postalCode = "postalcode"
        case country
        case company
        case email
        case phone
        case ssn
        case username
        case passportNumber = "passportnumber"
        case licenseNumber = "licensenumber"
    }
}

/// Secure-note payload.
public struct SecureNoteModel: Codable, Sendable, Equatable {
    public let type: SecureNoteType

    public init(type: SecureNoteType) {
        self.type = type
    }

    enum CodingKeys: String, CodingKey {
        case type
    }
}

/// SSH-key payload. All fields are EncString on the wire.
public struct SshKeyModel: Codable, Sendable, Equatable {
    public let privateKey: EncString?
    public let publicKey: EncString?
    public let keyFingerprint: EncString?

    public init(privateKey: EncString?, publicKey: EncString?, keyFingerprint: EncString?) {
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.keyFingerprint = keyFingerprint
    }

    enum CodingKeys: String, CodingKey {
        case privateKey = "privatekey"
        case publicKey = "publickey"
        case keyFingerprint = "keyfingerprint"
    }
}
