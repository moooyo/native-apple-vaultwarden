import Foundation

/// Errors thrown by the software WebAuthn authenticator.
public enum Fido2Error: Error, Equatable {
    /// A stored/imported credential key could not be parsed (e.g. bad PKCS8/X9.63 DER).
    case invalidKey
    /// ECDSA signing failed.
    case signFailed
}
