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
    public internal(set) var recentUseRank: Int?
    /// Raw WebAuthn credential id. Present only for passkeys.
    public let credentialID: Data?
    /// Raw WebAuthn user handle. Present only for passkeys.
    public let userHandle: Data?

    public var id: ID {
        ID(kind: kind, recordID: recordID, serviceIdentifier: serviceIdentifier,
           credentialID: credentialID)
    }

    public var displayHost: String? { Self.displayHost(for: serviceIdentifier) }

    var usageContext: String { Self.usageContext(for: kind, service: serviceIdentifier, credentialID: credentialID) }

    static func usageContext(for kind: Kind, service: String, credentialID: Data?) -> String {
        let host = displayHost(for: service) ?? ""
        switch kind {
        case .password: return "password|\(host)"
        case .oneTimeCode: return "code|\(host)"
        case .passkey: return "passkey|\(host)|\(credentialID?.base64EncodedString() ?? "")"
        }
    }

    public static func displayHost(for identifier: String) -> String? {
        let value = identifier.trimmingCharacters(in: .whitespacesAndNewlines)
        let address = value.contains("://") || value.hasPrefix("//") ? value : "//\(value)"
        guard var host = URLComponents(string: address)?.host?.lowercased() else { return nil }
        while host.hasSuffix(".") { host.removeLast() }
        let hostCharacters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._:[]"))
        guard !host.isEmpty, host.unicodeScalars.allSatisfy(hostCharacters.contains) else { return nil }
        return host
    }

    public func matchesSearch(_ query: String) -> Bool {
        query.isEmpty || name.localizedStandardContains(query) || user.localizedStandardContains(query)
            || displayHost?.localizedStandardContains(query) == true
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
        self.recentUseRank = nil
    }
}
