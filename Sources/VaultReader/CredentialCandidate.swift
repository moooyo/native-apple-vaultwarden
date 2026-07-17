import Foundation

/// Non-secret metadata for one credential the AutoFill extension may show in its
/// manual picker. Passwords, TOTP seeds, and passkey private keys are never returned.
public struct CredentialCandidate: Sendable, Equatable, Hashable, Identifiable {
    public enum Kind: Sendable, Equatable, Hashable {
        case password
        case oneTimeCode
        case passkey
    }

    /// A stable picker identity. A cipher can own more than one passkey, so `recordID`
    /// alone is not sufficient to identify a row in the UI.
    public struct ID: Sendable, Equatable, Hashable {
        public let kind: Kind
        public let recordID: String
        public let serviceIdentifier: String
        public let credentialID: Data?

        public init(kind: Kind, recordID: String, serviceIdentifier: String,
                    credentialID: Data?) {
            self.kind = kind
            self.recordID = recordID
            self.serviceIdentifier = serviceIdentifier
            self.credentialID = credentialID
        }
    }

    public let kind: Kind
    public let name: String
    public let user: String
    public let recordID: String
    /// A login URI for password/TOTP candidates, or the RP id for passkeys.
    public let serviceIdentifier: String
    /// Raw WebAuthn credential id. Present only for passkeys.
    public let credentialID: Data?
    /// Raw WebAuthn user handle. Present only for passkeys.
    public let userHandle: Data?

    public var id: ID {
        ID(kind: kind, recordID: recordID, serviceIdentifier: serviceIdentifier,
           credentialID: credentialID)
    }

    public init(kind: Kind, name: String, user: String, recordID: String,
                serviceIdentifier: String, credentialID: Data? = nil,
                userHandle: Data? = nil) {
        self.kind = kind
        self.name = name
        self.user = user
        self.recordID = recordID
        self.serviceIdentifier = serviceIdentifier
        self.credentialID = credentialID
        self.userHandle = userHandle
    }
}
