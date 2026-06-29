import Foundation
import CryptoKit

/// A P-256 (secp256r1 / prime256v1) credential keypair used for ES256 WebAuthn
/// passkeys. The private key is stored as PKCS#8 DER in `fido2Credentials.keyValue`.
public struct CredentialKey: Sendable {
    private let priv: P256.Signing.PrivateKey

    /// Generate a fresh P-256 key.
    public init() {
        priv = P256.Signing.PrivateKey()
    }

    /// Import from a stored PKCS#8 DER private key (the `keyValue`).
    ///
    /// On the Command Line Tools toolchain CryptoKit exposes the PKCS#8
    /// PrivateKeyInfo encoding as `derRepresentation` (verified to be a
    /// `SEQUENCE { version, AlgorithmIdentifier(ecPublicKey, prime256v1), ... }`),
    /// so that is what backs `pkcs8`/`exportPKCS8()`.
    public init(pkcs8 der: Data) throws {
        do { priv = try P256.Signing.PrivateKey(derRepresentation: der) }
        catch { throw Fido2Error.invalidKey }
    }

    /// Alternate import from an X9.63 private-key representation.
    public init(x963 der: Data) throws {
        do { priv = try P256.Signing.PrivateKey(x963Representation: der) }
        catch { throw Fido2Error.invalidKey }
    }

    /// Export as PKCS#8 DER for storage in `fido2Credentials.keyValue`.
    public func exportPKCS8() -> Data { priv.derRepresentation }

    /// Uncompressed X9.63 public point: `0x04 || X(32) || Y(32)` (65 bytes).
    public var publicKeyX963: Data { priv.publicKey.x963Representation }

    /// Sign `data` with ES256, returning the ASN.1 DER signature that WebAuthn requires.
    func sign(_ data: Data) throws -> Data {
        do { return try priv.signature(for: data).derRepresentation }
        catch { throw Fido2Error.signFailed }
    }

    /// The public key (for sign-then-verify round-trips).
    var publicKey: P256.Signing.PublicKey { priv.publicKey }
}
