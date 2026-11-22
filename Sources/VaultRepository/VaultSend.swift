import Foundation

public enum VaultSendKind: Int, Sendable, Hashable {
    case text, file
}

public struct VaultSend: Identifiable, Sendable, Equatable {
    public let id: String
    public let kind: VaultSendKind
    public let name: String
    public let text: String?
    public let fileName: String?
    public let hideText: Bool
    public let deletionDate: Date
    public let expirationDate: Date?
    public let accessCount: Int
    public let maxAccessCount: Int?
    public let hasPassword: Bool
    public let hideEmail: Bool
    public let disabled: Bool
    public let shareURL: URL
    public let revisionDate: Date
    public let notes: String?

    public init(id: String, kind: VaultSendKind, name: String, text: String? = nil,
                fileName: String? = nil, hideText: Bool = false, deletionDate: Date,
                expirationDate: Date? = nil, accessCount: Int = 0, maxAccessCount: Int? = nil,
                hasPassword: Bool = false, hideEmail: Bool = false, disabled: Bool = false,
                shareURL: URL, revisionDate: Date, notes: String? = nil) {
        self.id = id
        self.kind = kind
        self.name = name
        self.text = text
        self.fileName = fileName
        self.hideText = hideText
        self.deletionDate = deletionDate
        self.expirationDate = expirationDate
        self.accessCount = accessCount
        self.maxAccessCount = maxAccessCount
        self.hasPassword = hasPassword
        self.hideEmail = hideEmail
        self.disabled = disabled
        self.shareURL = shareURL
        self.revisionDate = revisionDate
        self.notes = notes
    }
}

public struct VaultSendDraft: Sendable {
    public var kind: VaultSendKind
    public var name: String
    public var text: String
    public var fileURL: URL?
    public var hideText: Bool
    public var deletionDate: Date
    public var expirationDate: Date?
    public var maxAccessCount: Int?
    public var password: String?
    public var removePassword: Bool
    public var hideEmail: Bool
    public var disabled: Bool
    public var notes: String?

    public init(kind: VaultSendKind, name: String, text: String = "", fileURL: URL? = nil,
                hideText: Bool = false, deletionDate: Date, expirationDate: Date? = nil,
                maxAccessCount: Int? = nil, password: String? = nil, removePassword: Bool = false,
                hideEmail: Bool = false, disabled: Bool = false, notes: String? = nil) {
        self.kind = kind
        self.name = name
        self.text = text
        self.fileURL = fileURL
        self.hideText = hideText
        self.deletionDate = deletionDate
        self.expirationDate = expirationDate
        self.maxAccessCount = maxAccessCount
        self.password = password
        self.removePassword = removePassword
        self.hideEmail = hideEmail
        self.disabled = disabled
        self.notes = notes
    }
}

public protocol VaultSendService: Sendable {
    func listSends() async throws -> [VaultSend]
    func createSend(_ draft: VaultSendDraft) async throws -> VaultSend
    func updateSend(id: String, draft: VaultSendDraft) async throws -> VaultSend
    func deleteSend(id: String) async throws
}
