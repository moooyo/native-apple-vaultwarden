import Foundation
import CryptoCore

/// A custom field attached to a cipher.
public struct FieldModel: Codable, Sendable, Equatable {
    public let type: FieldType
    public let name: EncString?
    public let value: EncString?
    public let linkedId: Int?

    public init(type: FieldType, name: EncString?, value: EncString?, linkedId: Int?) {
        self.type = type
        self.name = name
        self.value = value
        self.linkedId = linkedId
    }

    enum CodingKeys: String, CodingKey {
        case type
        case name
        case value
        case linkedId = "linkedid"
    }
}
