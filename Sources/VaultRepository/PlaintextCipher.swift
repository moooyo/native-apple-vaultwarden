import Foundation
import CryptoCore
import VaultModels

public struct PlaintextFolder: Sendable, Equatable, Identifiable, Hashable {
    public let id: String
    public let name: String

    public init(id: String, name: String) {
        self.id = id
        self.name = name
    }
}

public struct VaultListing: Sendable {
    public let active: [PlaintextCipher]
    public let archived: [PlaintextCipher]
    public let trash: [PlaintextCipher]
    public let folders: [PlaintextFolder]

    public init(active: [PlaintextCipher], archived: [PlaintextCipher], trash: [PlaintextCipher], folders: [PlaintextFolder]) {
        self.active = active
        self.archived = archived
        self.trash = trash
        self.folders = folders
    }
}

/// A decrypted, app-level cipher used as input to create/update and as output from reads.
/// The repository encrypts every string field under the cipher's per-item key when present
/// (otherwise the user key) and reconstructs all five Bitwarden cipher sub-payloads on read,
/// so editing one field never drops untouched data or its protected per-item key.
public struct PlaintextCipher: Sendable, Equatable {
    public var id: String?
    public var type: Int
    public var name: String
    public var notes: String?
    public var folderID: String?
    public var organizationID: String?
    /// The server-provided per-item key, still encrypted under the owning user/organization
    /// key. It is metadata, not plaintext key material, and must survive edit round-trips.
    public var protectedCipherKey: EncString?
    public var favorite: Bool
    public var revisionDate: Date?
    public var creationDate: Date?
    public var deletedDate: Date?
    public var archivedDate: Date?
    public var reprompt: Int
    public var login: Login?
    public var card: Card?
    public var identity: Identity?
    public var secureNote: SecureNote?
    public var sshKey: SshKey?
    public var fields: [Field]

    public struct Login: Sendable, Equatable {
        public var username: String?
        public var password: String?
        public var totp: String?
        public var uris: [Uri]
        public var fido2Credentials: [Fido2Credential]
        public var passwordRevisionDate: Date?

        public init(username: String? = nil, password: String? = nil,
                    totp: String? = nil, uris: [Uri] = [],
                    fido2Credentials: [Fido2Credential] = [],
                    passwordRevisionDate: Date? = nil) {
            self.username = username
            self.password = password
            self.totp = totp
            self.uris = uris
            self.fido2Credentials = fido2Credentials
            self.passwordRevisionDate = passwordRevisionDate
        }
    }

    public struct Uri: Codable, Sendable, Equatable {
        public var uri: String
        public var match: Int?
        public init(uri: String, match: Int? = nil) {
            self.uri = uri
            self.match = match
        }
    }

    public struct Fido2Credential: Codable, Sendable, Equatable {
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
            self.credentialId = credentialId
            self.keyType = keyType
            self.keyAlgorithm = keyAlgorithm
            self.keyCurve = keyCurve
            self.keyValue = keyValue
            self.rpId = rpId
            self.rpName = rpName
            self.userHandle = userHandle
            self.userName = userName
            self.userDisplayName = userDisplayName
            self.counter = counter
            self.discoverable = discoverable
            self.creationDate = creationDate
        }
    }

    public struct Card: Codable, Sendable, Equatable {
        public var cardholderName: String?
        public var brand: String?
        public var number: String?
        public var expMonth: String?
        public var expYear: String?
        public var code: String?

        public init(cardholderName: String? = nil, brand: String? = nil,
                    number: String? = nil, expMonth: String? = nil,
                    expYear: String? = nil, code: String? = nil) {
            self.cardholderName = cardholderName
            self.brand = brand
            self.number = number
            self.expMonth = expMonth
            self.expYear = expYear
            self.code = code
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
    }

    public struct SecureNote: Codable, Sendable, Equatable {
        public var type: Int
        public init(type: Int = SecureNoteType.generic.rawValue) { self.type = type }
    }

    public struct SshKey: Codable, Sendable, Equatable {
        public var privateKey: String?
        public var publicKey: String?
        public var keyFingerprint: String?

        public var isComplete: Bool {
            [privateKey, publicKey, keyFingerprint].allSatisfy { value in
                value?.contains { !$0.isWhitespace } == true
            }
        }

        public init(privateKey: String? = nil, publicKey: String? = nil,
                    keyFingerprint: String? = nil) {
            self.privateKey = privateKey
            self.publicKey = publicKey
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
            self.type = type
            self.name = name
            self.value = value
            self.linkedId = linkedId
        }
    }

    public init(id: String? = nil, type: Int = CipherType.login.rawValue, name: String,
                notes: String? = nil, folderID: String? = nil, organizationID: String? = nil,
                protectedCipherKey: EncString? = nil, favorite: Bool = false,
                reprompt: Int = 0, login: Login? = nil,
                card: Card? = nil, identity: Identity? = nil,
                secureNote: SecureNote? = nil, sshKey: SshKey? = nil,
                fields: [Field] = [], revisionDate: Date? = nil, creationDate: Date? = nil,
                deletedDate: Date? = nil, archivedDate: Date? = nil) {
        self.id = id
        self.type = type
        self.name = name
        self.notes = notes
        self.folderID = folderID
        self.organizationID = organizationID
        self.protectedCipherKey = protectedCipherKey
        self.favorite = favorite
        self.reprompt = reprompt
        self.login = login
        self.card = card
        self.identity = identity
        self.secureNote = secureNote
        self.sshKey = sshKey
        self.fields = fields
        self.revisionDate = revisionDate
        self.creationDate = creationDate
        self.deletedDate = deletedDate
        self.archivedDate = archivedDate
    }
}
