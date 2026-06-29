import Foundation
import CryptoCore

/// A vault folder. `name` is always present (an EncString).
public struct FolderResponse: Codable, Sendable, Equatable {
    public let id: String
    public let name: EncString
    public let revisionDate: Date

    public init(id: String, name: EncString, revisionDate: Date) {
        self.id = id
        self.name = name
        self.revisionDate = revisionDate
    }

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case revisionDate = "revisiondate"
    }
}
