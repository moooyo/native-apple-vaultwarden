import Foundation
import CryptoCore

/// The login payload of a cipher.
public struct LoginModel: Codable, Sendable, Equatable {
    public let username: EncString?
    public let password: EncString?
    public let totp: EncString?
    public let uris: [LoginUriModel]?
    public let fido2Credentials: [Fido2CredentialModel]?
    public let passwordRevisionDate: Date?

    public init(username: EncString?, password: EncString?, totp: EncString?,
                uris: [LoginUriModel]?, fido2Credentials: [Fido2CredentialModel]?,
                passwordRevisionDate: Date?) {
        self.username = username
        self.password = password
        self.totp = totp
        self.uris = uris
        self.fido2Credentials = fido2Credentials
        self.passwordRevisionDate = passwordRevisionDate
    }

    enum CodingKeys: String, CodingKey {
        case username
        case password
        case totp
        case uris
        case fido2Credentials = "fido2credentials"
        case passwordRevisionDate = "passwordrevisiondate"
    }
}

/// A single login URI and its match strategy.
public struct LoginUriModel: Codable, Sendable, Equatable {
    public let uri: EncString?
    public let match: UriMatchType?

    public init(uri: EncString?, match: UriMatchType?) {
        self.uri = uri
        self.match = match
    }

    enum CodingKeys: String, CodingKey {
        case uri
        case match
    }
}

/// A FIDO2 / passkey credential. All fields are EncString on the wire EXCEPT
/// `creationDate`, which is plaintext ISO-8601.
public struct Fido2CredentialModel: Codable, Sendable, Equatable {
    public let credentialId: EncString?
    public let keyType: EncString?
    public let keyAlgorithm: EncString?
    public let keyCurve: EncString?
    public let keyValue: EncString?
    public let rpId: EncString?
    public let rpName: EncString?
    public let userHandle: EncString?
    public let userName: EncString?
    public let userDisplayName: EncString?
    public let counter: EncString?
    public let discoverable: EncString?
    public let creationDate: Date?

    public init(credentialId: EncString?, keyType: EncString?, keyAlgorithm: EncString?,
                keyCurve: EncString?, keyValue: EncString?, rpId: EncString?, rpName: EncString?,
                userHandle: EncString?, userName: EncString?, userDisplayName: EncString?,
                counter: EncString?, discoverable: EncString?, creationDate: Date?) {
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

    enum CodingKeys: String, CodingKey {
        case credentialId = "credentialid"
        case keyType = "keytype"
        case keyAlgorithm = "keyalgorithm"
        case keyCurve = "keycurve"
        case keyValue = "keyvalue"
        case rpId = "rpid"
        case rpName = "rpname"
        case userHandle = "userhandle"
        case userName = "username"
        case userDisplayName = "userdisplayname"
        case counter
        case discoverable
        case creationDate = "creationdate"
    }
}
