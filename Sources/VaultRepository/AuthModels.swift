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

/// Keychain account names (within the shared access group) used by the auth flow.
enum KeychainAccounts {
    static let refreshToken = "tessera.refresh-token"
    static let localAuthHash = "tessera.local-auth-hash"
}
