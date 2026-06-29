import Foundation

/// RFC 4648 Base32 decoding (case-insensitive, padding-tolerant).
///
/// Used to decode TOTP secrets, which Bitwarden / authenticator apps store as
/// Base32 strings (optionally with spaces, dashes, or `=` padding).
public enum Base32 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    /// Decode a Base32 string into raw bytes.
    /// - Uppercases input and strips spaces, `=` padding, and `-` separators.
    /// - Returns `nil` if any character is outside the RFC 4648 alphabet.
    public static func decode(_ input: String) -> Data? {
        let cleaned = input.uppercased().filter { $0 != " " && $0 != "=" && $0 != "-" }
        if cleaned.isEmpty { return Data() }

        var lookup = [Character: UInt8]()
        for (i, c) in alphabet.enumerated() { lookup[c] = UInt8(i) }

        var bits = 0
        var value = 0
        var out = [UInt8]()
        for ch in cleaned {
            guard let v = lookup[ch] else { return nil }
            value = (value << 5) | Int(v)
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((value >> bits) & 0xff))
            }
        }
        return Data(out)
    }
}
