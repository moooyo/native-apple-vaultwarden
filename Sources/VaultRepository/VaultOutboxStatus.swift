public struct VaultOutboxStatus: Sendable, Equatable {
    public let pendingCount: Int
    public let issues: [VaultOutboxIssue]

    public init(pendingCount: Int = 0, issues: [VaultOutboxIssue] = []) {
        self.pendingCount = pendingCount
        self.issues = issues
    }
}

public struct VaultOutboxIssue: Sendable, Hashable, Identifiable {
    public enum Kind: String, Sendable, Hashable {
        case updateConflict, deleteConflict, rejectedCreate, unconfirmedCreate, accountKeyChanged
    }

    public let id: Int64
    public let kind: Kind
    public let itemName: String?
    public let canKeepLocalCopy: Bool
    public let localRevision: String?
    let session: AccountSessionLease?

    public init(id: Int64, kind: Kind, itemName: String?, canKeepLocalCopy: Bool, localRevision: String? = nil) {
        self.init(id: id, kind: kind, itemName: itemName, canKeepLocalCopy: canKeepLocalCopy,
                  localRevision: localRevision, session: nil)
    }

    init(id: Int64, kind: Kind, itemName: String?, canKeepLocalCopy: Bool,
         localRevision: String?, session: AccountSessionLease?) {
        self.id = id
        self.kind = kind
        self.itemName = itemName
        self.canKeepLocalCopy = canKeepLocalCopy
        self.localRevision = localRevision
        self.session = session
    }
}

public enum VaultOutboxAction: Sendable, Equatable {
    case useServer, keepLocalCopy
}
