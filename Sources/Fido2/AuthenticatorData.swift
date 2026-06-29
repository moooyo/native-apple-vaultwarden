import Foundation

/// WebAuthn authenticator data flags (the byte at offset 32 of `authenticatorData`).
public struct AuthenticatorFlags: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    /// UP — User Present.
    public static let userPresent  = AuthenticatorFlags(rawValue: 0x01)
    /// UV — User Verified.
    public static let userVerified = AuthenticatorFlags(rawValue: 0x04)
    /// AT — Attested credential data included.
    public static let attestedData = AuthenticatorFlags(rawValue: 0x40)
}
