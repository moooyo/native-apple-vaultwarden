import Foundation
import CryptoCore

/// Decodes `T` but never throws: on failure stores `nil` plus the error, so a
/// single bad element can't abort decoding an entire array (protocol-split defense).
public struct Failable<T: Decodable & Sendable>: Decodable, Sendable {
    public let value: T?
    public let error: String?

    public init(from decoder: any Decoder) throws {
        do { value = try T(from: decoder); error = nil }
        catch { value = nil; self.error = String(describing: error) }
    }
}

/// The `/api/sync` response. The `ciphers`, `folders`, and `collections` arrays
/// are each decoded element-by-element via `Failable`, so one malformed element
/// (e.g. an invalid EncString `name`) is dropped and flagged rather than aborting
/// the whole sync. The `profile` is the one deliberate exception — see below.
public struct SyncResponse: Decodable, Sendable {
    /// Intentionally REQUIRED (hard-fail), unlike the soft-failed arrays below.
    /// The profile carries the user key and RSA private key; without it the vault
    /// is unusable, so a corrupt or missing profile must fail loudly rather than
    /// silently yielding an empty, unopenable vault.
    public let profile: ProfileResponse

    private let folderSlots: [Failable<FolderResponse>]
    private let cipherSlots: [Failable<CipherResponse>]
    private let collectionSlots: [Failable<CollectionResponse>]?

    /// The ciphers that decoded successfully.
    public var ciphers: [CipherResponse] { cipherSlots.compactMap(\.value) }

    /// Error descriptions for ciphers that failed to decode (e.g. invalid EncString).
    public var droppedCipherErrors: [String] { cipherSlots.compactMap(\.error) }

    /// The folders that decoded successfully.
    public var folders: [FolderResponse] { folderSlots.compactMap(\.value) }

    /// Error descriptions for folders that failed to decode (e.g. invalid EncString).
    public var droppedFolderErrors: [String] { folderSlots.compactMap(\.error) }

    /// The collections that decoded successfully (nil if absent from the payload).
    public var collections: [CollectionResponse]? { collectionSlots?.compactMap(\.value) }

    /// Error descriptions for collections that failed to decode (e.g. invalid EncString).
    public var droppedCollectionErrors: [String] { collectionSlots?.compactMap(\.error) ?? [] }

    enum CodingKeys: String, CodingKey {
        case profile
        case folderSlots = "folders"
        case cipherSlots = "ciphers"
        case collectionSlots = "collections"
    }
}
