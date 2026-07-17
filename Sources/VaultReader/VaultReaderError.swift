import Foundation

/// Errors surfaced by `VaultReader`, the AutoFill extension's least-privilege facade.
///
/// These map cleanly onto what the extension can show or how it must fail: a `.locked`
/// vault means the extension should drive the biometric-unlock UI; `.notFound` means the
/// selected record is gone; `.noPasswordField` / `.noPasskey` mean the chosen record
/// can't satisfy the request kind; `.noOneTimeCode` means no TOTP value is present;
/// `.malformed` means a stored blob/credential could not be parsed (corrupt cache).
public enum VaultReaderError: Error, Equatable, Sendable {
    /// The vault is locked — no decryption is possible until unlock succeeds.
    case locked
    /// No cipher exists for the requested record id.
    case notFound
    /// The cipher is not a login / has no username+password to vend.
    case noPasswordField
    /// The cipher is not a login or has no TOTP value to vend.
    case noOneTimeCode
    /// The cipher has no usable FIDO2 / passkey credential.
    case noPasskey
    /// A stored blob, EncString, or credential key could not be parsed.
    case malformed
}
