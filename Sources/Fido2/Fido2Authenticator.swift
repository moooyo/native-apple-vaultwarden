import Foundation
import CryptoKit

/// Stateless software WebAuthn authenticator: builds `authenticatorData` and
/// performs ES256 (P-256) assertion signing. Registration lives in an extension
/// (`Fido2Authenticator+Registration.swift`).
public enum Fido2Authenticator {
    /// authenticatorData = SHA256(rpId) || flags(1) || signCount(4, big-endian) [|| attestedCredentialData]
    public static func authenticatorData(rpId: String,
                                         flags: AuthenticatorFlags,
                                         signCount: UInt32,
                                         attestedCredentialData: Data? = nil) -> Data {
        var d = Data(SHA256.hash(data: Data(rpId.utf8)))
        d.append(flags.rawValue)
        d.append(contentsOf: withUnsafeBytes(of: signCount.bigEndian) { Array($0) })
        if let acd = attestedCredentialData { d.append(acd) }
        return d
    }

    /// WebAuthn assertion: returns the authenticatorData and the DER ECDSA signature
    /// over (authenticatorData || clientDataHash). The UP flag is always set; UV is set
    /// when `userVerified` is true.
    public static func assert(rpId: String,
                              clientDataHash: Data,
                              signCount: UInt32,
                              userVerified: Bool,
                              key: CredentialKey) throws
        -> (authenticatorData: Data, signature: Data) {
        var flags: AuthenticatorFlags = [.userPresent]
        if userVerified { flags.insert(.userVerified) }
        let authData = authenticatorData(rpId: rpId, flags: flags, signCount: signCount)
        let signature = try key.sign(authData + clientDataHash)
        return (authData, signature)
    }
}
