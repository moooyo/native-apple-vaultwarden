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

/// The `/api/sync` response. The `ciphers` array is decoded element-by-element
/// via `Failable` so one malformed cipher (e.g. an invalid EncString `name`) is
/// dropped and flagged rather than aborting the whole sync.
public struct SyncResponse: Decodable, Sendable {
    public let profile: ProfileResponse
    public let folders: [FolderResponse]
    private let cipherSlots: [Failable<CipherResponse>]
    public let collections: [CollectionResponse]?

    /// The ciphers that decoded successfully.
    public var ciphers: [CipherResponse] { cipherSlots.compactMap(\.value) }

    /// Error descriptions for ciphers that failed to decode (e.g. invalid EncString).
    public var droppedCipherErrors: [String] { cipherSlots.compactMap(\.error) }

    enum CodingKeys: String, CodingKey {
        case profile
        case folders
        case cipherSlots = "ciphers"
        case collections
    }
}
