import Foundation

/// Value types mirroring the persistence schema (design spec §7.3).
///
/// Convention: `enc*` fields hold EncString **wire strings** (TEXT) — decryption
/// happens in the repository/KeyVault, never here. Plaintext metadata columns
/// (type, dates, flags, `searchText`) exist only for local query/sort/search and
/// live inside the encrypted DB. All row types are `Sendable` so they cross the
/// `VaultStore` actor boundary.

/// A row in the `cipher` table (+ a denormalized convenience for the schema columns).
public struct CipherRow: Sendable, Equatable {
    public let id: String
    public let accountID: String
    public let type: Int
    public let folderID: String?
    public let organizationID: String?
    public let favorite: Bool
    public let reprompt: Int
    public let edit: Bool
    public let viewPassword: Bool
    public let revisionDate: String
    public let creationDate: String
    public let deletedDate: String?
    public let encName: String?
    public let encNotes: String?
    public let encBlob: String?
    public let encCipherKey: String?
    /// Plaintext, decrypted searchable text (names/usernames/uris). Lives only inside
    /// the encrypted DB; built by the repository when upserting.
    public let searchText: String?

    public init(
        id: String,
        accountID: String,
        type: Int,
        folderID: String? = nil,
        organizationID: String? = nil,
        favorite: Bool = false,
        reprompt: Int = 0,
        edit: Bool = true,
        viewPassword: Bool = true,
        revisionDate: String,
        creationDate: String,
        deletedDate: String? = nil,
        encName: String? = nil,
        encNotes: String? = nil,
        encBlob: String? = nil,
        encCipherKey: String? = nil,
        searchText: String? = nil
    ) {
        self.id = id
        self.accountID = accountID
        self.type = type
        self.folderID = folderID
        self.organizationID = organizationID
        self.favorite = favorite
        self.reprompt = reprompt
        self.edit = edit
        self.viewPassword = viewPassword
        self.revisionDate = revisionDate
        self.creationDate = creationDate
        self.deletedDate = deletedDate
        self.encName = encName
        self.encNotes = encNotes
        self.encBlob = encBlob
        self.encCipherKey = encCipherKey
        self.searchText = searchText
    }
}

/// A row in the `folder` table.
public struct FolderRow: Sendable, Equatable {
    public let id: String
    public let accountID: String
    public let encName: String?
    public let revisionDate: String

    public init(id: String, accountID: String, encName: String? = nil, revisionDate: String) {
        self.id = id
        self.accountID = accountID
        self.encName = encName
        self.revisionDate = revisionDate
    }
}

/// A row in the `sync_state` table (one per account).
public struct SyncStateRow: Sendable, Equatable {
    public let accountID: String
    public let lastAccountRevision: String?
    public let lastFullSyncAt: String?

    public init(accountID: String, lastAccountRevision: String? = nil, lastFullSyncAt: String? = nil) {
        self.accountID = accountID
        self.lastAccountRevision = lastAccountRevision
        self.lastFullSyncAt = lastFullSyncAt
    }
}

/// A row in the `outbox` table (a pending outbound write). `id` is the autoincrement
/// rowid; it is `nil` before insertion and populated when read back.
public struct OutboxRow: Sendable, Equatable {
    public let id: Int64?
    public let opType: String
    public let entityType: String
    public let entityID: String
    public let payloadJSON: String
    public let lastKnownRevisionDate: String?

    public init(
        id: Int64? = nil,
        opType: String,
        entityType: String,
        entityID: String,
        payloadJSON: String,
        lastKnownRevisionDate: String? = nil
    ) {
        self.id = id
        self.opType = opType
        self.entityType = entityType
        self.entityID = entityID
        self.payloadJSON = payloadJSON
        self.lastKnownRevisionDate = lastKnownRevisionDate
    }
}
