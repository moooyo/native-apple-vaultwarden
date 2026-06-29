import Foundation

/// Encodes a P-256 public key as a COSE_Key map (RFC 8152) for WebAuthn
/// attested credential data: EC2 key type, ES256 algorithm, P-256 curve.
public enum COSEKey {
    /// COSE_Key for an EC2 / ES256 / P-256 public key from an X9.63 uncompressed point.
    ///
    /// Map = `{1:2 (kty EC2), 3:-7 (alg ES256), -1:1 (crv P-256), -2:<32B X>, -3:<32B Y>}`.
    public static func encode(publicKeyX963 point: Data) -> Data {
        precondition(point.count == 65 && point[point.startIndex] == 0x04,
                     "publicKeyX963 must be a 65-byte uncompressed point (0x04 || X || Y)")
        let base = point.startIndex
        let x = point.subdata(in: point.index(base, offsetBy: 1)..<point.index(base, offsetBy: 33))
        let y = point.subdata(in: point.index(base, offsetBy: 33)..<point.index(base, offsetBy: 65))
        return CBOR.map([
            (.int(1), .int(2)),    // kty: EC2
            (.int(3), .int(-7)),   // alg: ES256
            (.int(-1), .int(1)),   // crv: P-256
            (.int(-2), .bytes(x)),
            (.int(-3), .bytes(y)),
        ]).encoded()
    }
}
