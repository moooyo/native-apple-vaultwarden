import Foundation

/// Minimal CBOR (RFC 8949) encoder — only the value kinds needed by WebAuthn's
/// `attestationObject` and COSE_Key encodings. Definite-length only.
///
/// Major types used:
/// - 0: unsigned integer
/// - 1: negative integer (value = -1 - argument)
/// - 2: byte string
/// - 3: text string (UTF-8)
/// - 4: array
/// - 5: map
public enum CBOR {
    case uint(UInt64)
    case negint(UInt64) // value = -1 - n
    case bytes(Data)
    case text(String)
    case array([CBOR])
    case map([(CBOR, CBOR)])

    public func encoded() -> Data {
        switch self {
        case .uint(let n):
            return CBOR.head(0, n)
        case .negint(let n):
            return CBOR.head(1, n) // caller passes (-1 - value)
        case .bytes(let d):
            return CBOR.head(2, UInt64(d.count)) + d
        case .text(let s):
            let d = Data(s.utf8)
            return CBOR.head(3, UInt64(d.count)) + d
        case .array(let a):
            return a.reduce(CBOR.head(4, UInt64(a.count))) { $0 + $1.encoded() }
        case .map(let m):
            // Key order is the caller's responsibility: this encoder emits keys in the
            // order given and does NOT sort to CTAP2 canonical order. Current callers
            // (COSE_Key, attestationObject) hand-order their keys correctly.
            return m.reduce(CBOR.head(5, UInt64(m.count))) { $0 + $1.0.encoded() + $1.1.encoded() }
        }
    }

    /// Convenience: signed integer → uint (major 0) or negint (major 1).
    public static func int(_ v: Int) -> CBOR {
        v >= 0 ? .uint(UInt64(v)) : .negint(UInt64(-1 - v))
    }

    /// Encode the initial byte(s): `(major << 5) | argument` with 24/25/26/27 length forms.
    private static func head(_ major: UInt8, _ n: UInt64) -> Data {
        let m = major << 5
        switch n {
        case 0...23:
            return Data([m | UInt8(n)])
        case 24...0xff:
            return Data([m | 24, UInt8(n)])
        case 0x100...0xffff:
            return Data([m | 25]) + be(n, 2)
        case 0x10000...0xffff_ffff:
            return Data([m | 26]) + be(n, 4)
        default:
            return Data([m | 27]) + be(n, 8)
        }
    }

    private static func be(_ n: UInt64, _ bytes: Int) -> Data {
        Data((0..<bytes).reversed().map { UInt8((n >> (8 * $0)) & 0xff) })
    }
}
