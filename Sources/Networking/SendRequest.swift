import CryptoCore
import Foundation
import VaultModels

public struct SendRequest: Encodable, Sendable {
    public struct TextPayload: Encodable, Sendable {
        public let text: EncString
        public let hidden: Bool

        public init(text: EncString, hidden: Bool) { self.text = text; self.hidden = hidden }
    }

    public struct FilePayload: Encodable, Sendable {
        public let fileName: EncString

        public init(fileName: EncString) { self.fileName = fileName }
    }

    public let type: Int
    public let key: EncString
    public let name: EncString
    public var notes: EncString?
    public var text: TextPayload?
    public var file: FilePayload?
    public var fileLength: Int?
    public var password: String?
    public var maxAccessCount: Int?
    public var expirationDate: Date?
    public let deletionDate: Date
    public var hideEmail: Bool
    public var disabled: Bool

    public init(type: Int, key: EncString, name: EncString, deletionDate: Date,
                hideEmail: Bool, disabled: Bool) {
        self.type = type
        self.key = key
        self.name = name
        self.deletionDate = deletionDate
        self.hideEmail = hideEmail
        self.disabled = disabled
    }
}

public struct SendUploadResponse: Decodable, Sendable {
    public let fileUploadType: Int
    public let sendResponse: SendResponse

    enum CodingKeys: String, CodingKey {
        case fileUploadType = "fileuploadtype", sendResponse = "sendresponse"
    }
}
