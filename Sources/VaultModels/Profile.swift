import Foundation
import CryptoCore

/// The account profile carried in a sync response.
public struct ProfileResponse: Codable, Sendable, Equatable {
    public let id: String
    public let email: String
    public let name: String?
    public let key: EncString?
    public let privateKey: EncString?
    public let organizations: [OrganizationModel]?
    public let securityStamp: String?

    public init(id: String, email: String, name: String?, key: EncString?,
                privateKey: EncString?, organizations: [OrganizationModel]?, securityStamp: String?) {
        self.id = id
        self.email = email
        self.name = name
        self.key = key
        self.privateKey = privateKey
        self.organizations = organizations
        self.securityStamp = securityStamp
    }

    enum CodingKeys: String, CodingKey {
        case id
        case email
        case name
        case key
        case privateKey = "privatekey"
        case organizations
        case securityStamp = "securitystamp"
    }
}

/// Minimal organization model — full organization handling is M2.
public struct OrganizationModel: Codable, Sendable, Equatable {
    public let id: String
    public let name: String?
    public let key: EncString?

    public init(id: String, name: String?, key: EncString?) {
        self.id = id
        self.name = name
        self.key = key
    }

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case key
    }
}

/// Minimal collection model — full collection handling is a later milestone.
public struct CollectionResponse: Codable, Sendable, Equatable {
    public let id: String
    public let organizationId: String
    public let name: EncString?

    public init(id: String, organizationId: String, name: EncString?) {
        self.id = id
        self.organizationId = organizationId
        self.name = name
    }

    enum CodingKeys: String, CodingKey {
        case id
        case organizationId = "organizationid"
        case name
    }
}
