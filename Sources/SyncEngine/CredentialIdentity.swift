import Foundation

/// A single AutoFill credential identity, decoupled from `AuthenticationServices`.
///
/// The real AutoFill store (`ASCredentialIdentityStore`) is only available inside a
/// signed app/extension with the AutoFill entitlement, so `SyncEngine` works against
/// this plain value type and a `CredentialIdentityWriting` seam. The Xcode-gated
/// conformer maps these values to `ASPasswordCredentialIdentity` /
/// `ASPasskeyCredentialIdentity` / `ASOneTimeCodeCredentialIdentity`.
public struct CredentialIdentity: Sendable, Equatable, Hashable {
    /// Canonical owner used to produce an opaque account-bound system record identifier.
    public let accountID: String
    /// What kind of identity this is — drives which `AS*CredentialIdentity` subtype
    /// the writer creates.
    public enum Kind: Sendable, Equatable, Hashable {
        case password
        case passkey
        case otp
    }

    /// The vault record this identity points back to (the cipher id). Returned by the
    /// system when the user picks this identity, so the extension can decrypt the one
    /// selected item.
    public let recordID: String
    /// For passwords/OTP this is the service identifier (the URI/domain); for passkeys
    /// it is the relying-party id (`rpId`).
    public let serviceIdentifier: String
    /// The username / login shown in the AutoFill picker.
    public let user: String
    public let kind: Kind
    /// The raw WebAuthn credential id for a passkey identity. Password and OTP
    /// identities leave this `nil`.
    public let credentialID: Data?
    /// The raw WebAuthn user handle for a passkey identity. Password and OTP
    /// identities leave this `nil`.
    public let userHandle: Data?

    public init(accountID: String, recordID: String,
                serviceIdentifier: String, user: String, kind: Kind,
                credentialID: Data? = nil, userHandle: Data? = nil) {
        self.accountID = accountID
        self.recordID = recordID
        self.serviceIdentifier = serviceIdentifier
        self.user = user
        self.kind = kind
        self.credentialID = credentialID
        self.userHandle = userHandle
    }
}

/// The write side of the AutoFill credential-identity store, abstracted for testing.
///
/// `SyncEngine` rebuilds the system AutoFill index after each sync. Whether it does a
/// full replace or an incremental add/remove depends on `supportsIncremental()` (the
/// real store advertises this via `ASCredentialIdentityStoreState.supportsIncrementalUpdates`).
public protocol CredentialIdentityWriting: Sendable {
    /// Replace the entire saved identity set with `identities`.
    func replaceAll(_ identities: [CredentialIdentity]) async
    /// Apply an incremental delta to the saved identity set.
    func incremental(add: [CredentialIdentity], remove: [CredentialIdentity]) async
    /// Whether AutoFill is enabled by the user for this app. When `false`, the OS
    /// rejects writes, so `SyncEngine` skips the rebuild entirely.
    func isEnabled() async -> Bool
    /// Whether the store supports incremental updates (vs. requiring a full replace).
    func supportsIncremental() async -> Bool
}
