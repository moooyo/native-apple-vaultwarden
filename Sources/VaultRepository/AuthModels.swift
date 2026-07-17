import Foundation
import VaultModels
import Networking

/// The outcome of a `login` (or `submitTwoFactor`) attempt.
public enum LoginResult: Sendable, Equatable {
    /// Authentication succeeded and the vault is unlocked.
    case success
    /// The server requires a second factor; call `submitTwoFactor` with one of `providers`.
    case twoFactorRequired([TwoFactorProvider])
}

/// Identifies a logged-in account and the parameters needed to re-derive / unlock its key.
/// Held by `AuthRepository` after a successful login so master-password / biometric unlock
/// and sync can find the right account row.
public struct AccountSession: Sendable, Equatable {
    public let accountID: String
    public let email: String
    public let kdfIterations: Int
    /// The protected (type-2 wrapped) user key wire string from the token/sync response.
    public let protectedUserKey: String

    public init(accountID: String, email: String, kdfIterations: Int, protectedUserKey: String) {
        self.accountID = accountID
        self.email = email
        self.kdfIterations = kdfIterations
        self.protectedUserKey = protectedUserKey
    }
}

/// A point-in-time lease on one in-memory session incarnation. `generation` changes on
/// login, restore, lock, and logout, so an A -> B -> A transition cannot validate stale work
/// merely because the canonical account id happens to match again.
public struct AccountSessionLease: Sendable, Equatable {
    public let accountID: String
    public let generation: UInt64

    public init(accountID: String, generation: UInt64) {
        self.accountID = accountID
        self.generation = generation
    }
}
