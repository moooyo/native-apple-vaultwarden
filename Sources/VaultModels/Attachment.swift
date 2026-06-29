import Foundation
import CryptoCore

/// A file attachment on a cipher.
public struct AttachmentModel: Codable, Sendable, Equatable {
    public let id: String?
    public let url: String?
    public let fileName: EncString?
    public let key: EncString?
    public let size: String?
    public let sizeName: String?

    public init(id: String?, url: String?, fileName: EncString?, key: EncString?,
                size: String?, sizeName: String?) {
        self.id = id
        self.url = url
        self.fileName = fileName
        self.key = key
        self.size = size
        self.sizeName = sizeName
    }

    enum CodingKeys: String, CodingKey {
        case id
        case url
        case fileName = "filename"
        case key
        case size
        case sizeName = "sizename"
    }
}
