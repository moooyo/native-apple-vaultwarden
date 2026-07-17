import Foundation

/// Value types mirroring the persistence schema (design spec §7.3).
///
/// Convention: `enc*` fields hold EncString **wire strings** (TEXT) — decryption
/// happens in the repository/KeyVault, never here. Plaintext metadata columns
/// (type, dates, flags, `searchText`) exist only for local query/sort/search and
/// live inside the encrypted DB. All row types are `Sendable` so they cross the
/// `VaultStore` actor boundary.

/// A row in the `account` table. Ciphers/folders/etc. reference `account(id)` via
/// ON DELETE CASCADE foreign keys, so an account must exist before its children.
public struct AccountRow: Sendable, Equatable {
    public let id: String
    public let email: String?
    public let serverURL: String?
    public let kdfType: Int?
    public let kdfIters: Int?
    public let revisionDate: String?
    public let securityStamp: String?
    public let encUserKey: String?
    public let encPrivateKey: String?

    public init(
        id: String,
        email: String? = nil,
        serverURL: String? = nil,
        kdfType: Int? = nil,
        kdfIters: Int? = nil,
        revisionDate: String? = nil,
        securityStamp: String? = nil,
        encUserKey: String? = nil,
        encPrivateKey: String? = nil
    ) {
        self.id = id
        self.email = email
        self.serverURL = serverURL
        self.kdfType = kdfType
        self.kdfIters = kdfIters
        self.revisionDate = revisionDate
        self.securityStamp = securityStamp
        self.encUserKey = encUserKey
        self.encPrivateKey = encPrivateKey
    }
}

/// A row in the `cipher_uri` table. `matchType` is plaintext (for AutoFill matching);
/// `encURI` is an EncString wire string. Cascades on parent-cipher delete.
public struct CipherURIRow: Sendable, Equatable {
    public let id: String
    public let accountID: String
    public let cipherID: String
    public let encURI: String?
    public let matchType: Int?

    public init(
        id: String,
        accountID: String,
        cipherID: String,
        encURI: String? = nil,
        matchType: Int? = nil
    ) {
        self.id = id
        self.accountID = accountID
        self.cipherID = cipherID
        self.encURI = encURI
        self.matchType = matchType
    }
}

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
    public let accountID: String
    public let opType: String
    public let entityType: String
    public let entityID: String
    public let payloadJSON: String
    public let lastKnownRevisionDate: String?

    public init(
        id: Int64? = nil,
        accountID: String,
        opType: String,
        entityType: String,
        entityID: String,
        payloadJSON: String,
        lastKnownRevisionDate: String? = nil
    ) {
        self.id = id
        self.accountID = accountID
        self.opType = opType
        self.entityType = entityType
        self.entityID = entityID
        self.payloadJSON = payloadJSON
        self.lastKnownRevisionDate = lastKnownRevisionDate
    }
}
