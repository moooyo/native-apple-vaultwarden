import Foundation
import VaultModels

public enum EmergencyAccessType: Sendable, Equatable, Decodable {
    case view, takeover, unknown(Int)

    public init(from decoder: any Decoder) throws {
        switch try decoder.singleValueContainer().decode(Int.self) {
        case 0: self = .view
        case 1: self = .takeover
        case let value: self = .unknown(value)
        }
    }
}

public enum EmergencyAccessStatus: Sendable, Equatable, Decodable {
    case invited, accepted, confirmed, recoveryInitiated, recoveryApproved, unknown(Int)

    public init(from decoder: any Decoder) throws {
        switch try decoder.singleValueContainer().decode(Int.self) {
        case 0: self = .invited
        case 1: self = .accepted
        case 2: self = .confirmed
        case 3: self = .recoveryInitiated
        case 4: self = .recoveryApproved
        case let value: self = .unknown(value)
        }
    }
}

public enum EmergencyAccessDirection: String, Sendable {
    /// This account grants access to a trusted contact.
    case trusted
    /// Another account grants access to this account.
    case granted
}

/// Vaultwarden 1.37.5 does not expose the recovery start time or the deadline in either list.
/// `waitTimeDays` is the configured duration, not the number of days remaining.
public struct EmergencyAccessContact: Decodable, Sendable, Equatable, Identifiable {
    public let id: UUID
    public let direction: EmergencyAccessDirection
    public let contactID: UUID
    public let email: String
    public let name: String?
    public let type: EmergencyAccessType
    public let status: EmergencyAccessStatus
    public let waitTimeDays: Int

    private enum CodingKeys: String, CodingKey {
        case id, object, email, name, type, status
        case grantorID = "grantorid"
        case granteeID = "granteeid"
        case waitTimeDays = "waittimedays"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(String.self, forKey: .object) {
        case "emergencyAccessGranteeDetails":
            direction = .trusted
            contactID = try container.decode(UUID.self, forKey: .granteeID)
        case "emergencyAccessGrantorDetails":
            direction = .granted
            contactID = try container.decode(UUID.self, forKey: .grantorID)
        default:
            throw DecodingError.dataCorruptedError(forKey: .object, in: container,
                                                  debugDescription: "Unexpected emergency access record")
        }
        id = try container.decode(UUID.self, forKey: .id)
        email = try container.decode(String.self, forKey: .email)
        name = try container.decodeIfPresent(String.self, forKey: .name)
        type = try container.decode(EmergencyAccessType.self, forKey: .type)
        status = try container.decode(EmergencyAccessStatus.self, forKey: .status)
        waitTimeDays = try container.decode(Int.self, forKey: .waitTimeDays)
    }
}

package struct EmergencyAccessListResponse: Decodable, Sendable {
    package let data: [EmergencyAccessContact]
    package let object: String
    package let continuationToken: String?

    private enum CodingKeys: String, CodingKey {
        case data, object
        case continuationToken = "continuationtoken"
    }
}

package struct EmergencyAccessMutationResponse: Decodable, Sendable {
    package let id: UUID
    package let object: String
    package let type: EmergencyAccessType
    package let status: EmergencyAccessStatus
    package let waitTimeDays: Int

    private enum CodingKeys: String, CodingKey {
        case id, object, type, status
        case waitTimeDays = "waittimedays"
    }
}

package struct EmergencyAccessPublicKeyResponse: Decodable, Sendable {
    package let userID: UUID
    package let publicKey: String
    package let object: String

    private enum CodingKeys: String, CodingKey {
        case userID = "userid"
        case publicKey = "publickey"
        case object
    }
}

package struct EmergencyAccessViewResponse: Decodable, Sendable {
    /// A malformed or unsupported individual cipher need not hide the rest of the vault.
    package struct Item: Decodable, Sendable {
        package let cipher: CipherResponse?
        package let isExplicitlyPersonal: Bool

        private enum CodingKeys: String, CodingKey { case organizationID = "organizationid" }

        package init(from decoder: any Decoder) throws {
            cipher = try? CipherResponse(from: decoder)
            if let container = try? decoder.container(keyedBy: CodingKeys.self) {
                isExplicitlyPersonal = container.contains(.organizationID)
                    && (try? container.decodeNil(forKey: .organizationID)) == true
            } else {
                isExplicitlyPersonal = false
            }
        }
    }

    package let object: String
    package let keyEncrypted: String
    package let ciphers: [Item]

    private enum CodingKeys: String, CodingKey {
        case object, ciphers
        case keyEncrypted = "keyencrypted"
    }
}

package struct EmergencyAccessInviteRequest: Encodable, Sendable {
    package let email: String
    private let type = 0 // View only. Account takeover is not a native action.
    package let waitTimeDays: Int

    package init(email: String, waitTimeDays: Int) {
        self.email = email
        self.waitTimeDays = waitTimeDays
    }
}

package struct EmergencyAccessUpdateRequest: Encodable, Sendable {
    private let type = 0
    package let waitTimeDays: Int

    package init(waitTimeDays: Int) { self.waitTimeDays = waitTimeDays }
}

package struct EmergencyAccessAcceptRequest: Encodable, Sendable {
    private let token: String

    package init(token: String) { self.token = token }
}

package struct EmergencyAccessConfirmRequest: Encodable, Sendable {
    private let key: String

    package init(wrappedKey: String) { self.key = wrappedKey }
}
