import Foundation
import VaultModels

/// A decrypted, app-level cipher used as input to create/update and as output from reads.
/// The repository encrypts these fields under the user key on write, and decrypts store
/// rows into these on read. M1 covers logins + secure notes (the common paths); other
/// types carry just name/notes/type.
public struct PlaintextCipher: Sendable, Equatable {
    public var id: String?
    public var type: Int
    public var name: String
    public var notes: String?
    public var folderID: String?
    public var favorite: Bool
    public var reprompt: Int
    public var login: Login?

    public struct Login: Sendable, Equatable {
        public var username: String?
        public var password: String?
        public var totp: String?
        public var uris: [Uri]

        public init(username: String? = nil, password: String? = nil,
                    totp: String? = nil, uris: [Uri] = []) {
            self.username = username
            self.password = password
            self.totp = totp
            self.uris = uris
        }
    }

    public struct Uri: Sendable, Equatable {
        public var uri: String
        public var match: Int?
        public init(uri: String, match: Int? = nil) {
            self.uri = uri
            self.match = match
        }
    }

    public init(id: String? = nil, type: Int = CipherType.login.rawValue, name: String,
                notes: String? = nil, folderID: String? = nil, favorite: Bool = false,
                reprompt: Int = 0, login: Login? = nil) {
        self.id = id
        self.type = type
        self.name = name
        self.notes = notes
        self.folderID = folderID
        self.favorite = favorite
        self.reprompt = reprompt
        self.login = login
    }
}
