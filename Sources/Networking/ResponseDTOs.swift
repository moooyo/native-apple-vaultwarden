import Foundation

/// Response to attachment-upload step 1 (`POST /api/ciphers/{id}/attachment/v2`).
/// `url` is where the encrypted blob is uploaded in step 2; `fileUploadType`
/// selects the transport (0 = Direct to the Vaultwarden/Bitwarden server,
/// 1 = Azure). Decoded with the case-insensitive `VaultJSON.decoder()`.
public struct AttachmentUploadResponse: Decodable, Sendable, Equatable {
    public let attachmentId: String
    public let url: URL
    public let fileUploadType: Int

    public init(attachmentId: String, url: URL, fileUploadType: Int) {
        self.attachmentId = attachmentId
        self.url = url
        self.fileUploadType = fileUploadType
    }

    enum CodingKeys: String, CodingKey {
        case attachmentId = "attachmentid"
        case url
        case fileUploadType = "fileuploadtype"
    }
}

/// File-upload transport selected by the server in `AttachmentUploadResponse`.
public enum FileUploadType: Int, Sendable {
    case direct = 0
    case azure = 1
}

/// Minimal `/api/config` response. Vaultwarden emits camelCase, official Bitwarden
/// PascalCase; the case-insensitive decoder folds both. Only fields the client
/// currently needs are modeled; the rest are ignored.
public struct ServerConfig: Decodable, Sendable, Equatable {
    public let version: String?
    public let gitHash: String?

    public init(version: String?, gitHash: String?) {
        self.version = version
        self.gitHash = gitHash
    }

    enum CodingKeys: String, CodingKey {
        case version
        case gitHash = "githash"
    }
}
