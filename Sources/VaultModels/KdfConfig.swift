import Foundation

/// Prelogin (`/api/accounts/prelogin`) response: the KDF parameters needed to
/// derive the master key.
///
/// PBKDF2-only (D6): VaultModels models all four KDF fields for fidelity, but the
/// auth layer (a later plan) rejects `kdf != 0`. VaultModels itself does not enforce.
public struct PreloginResponse: Codable, Sendable, Equatable {
    public let kdf: Int
    public let kdfIterations: Int
    public let kdfMemory: Int?
    public let kdfParallelism: Int?

    public init(kdf: Int, kdfIterations: Int, kdfMemory: Int?, kdfParallelism: Int?) {
        self.kdf = kdf
        self.kdfIterations = kdfIterations
        self.kdfMemory = kdfMemory
        self.kdfParallelism = kdfParallelism
    }

    enum CodingKeys: String, CodingKey {
        case kdf
        case kdfIterations = "kdfiterations"
        case kdfMemory = "kdfmemory"
        case kdfParallelism = "kdfparallelism"
    }
}
