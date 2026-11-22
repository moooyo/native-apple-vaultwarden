import CryptoCore
import Foundation

public struct SendResponse: Codable, Sendable {
    public let id: String
    public let accessId: String
    public let type: SendType
    public let key: EncString
    public let name: EncString
    public let notes: EncString?
    public let text: TextPayload?
    public let file: FilePayload?
    public let password: String?
    public let authType: Int?
    public let maxAccessCount: Int?
    public let accessCount: Int
    public let disabled: Bool
    public let hideEmail: Bool?
    public let revisionDate: Date
    public let expirationDate: Date?
    public let deletionDate: Date

    public struct TextPayload: Codable, Sendable {
        public let text: EncString?
        public let hidden: Bool
    }

    public struct FilePayload: Codable, Sendable {
        public let id: String
        public let fileName: EncString

        enum CodingKeys: String, CodingKey { case id, fileName = "filename" }
    }

    enum CodingKeys: String, CodingKey {
        case id, type, key, name, notes, text, file, password, disabled
        case accessId = "accessid", authType = "authtype", maxAccessCount = "maxaccesscount"
        case accessCount = "accesscount", hideEmail = "hideemail", revisionDate = "revisiondate"
        case expirationDate = "expirationdate", deletionDate = "deletiondate"
    }
}
