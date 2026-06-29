import Foundation
import CryptoKit

/// Hash algorithm used by the HMAC step of TOTP/HOTP.
public enum TOTPAlgorithm: String, Sendable {
    case sha1 = "SHA1"
    case sha256 = "SHA256"
    case sha512 = "SHA512"
}

/// A fully-resolved TOTP configuration (decoded secret + parameters).
public struct TOTPConfiguration: Sendable, Equatable {
    public var secret: Data          // decoded key bytes
    public var algorithm: TOTPAlgorithm
    public var digits: Int           // 6 (or 8); Steam uses 5 chars
    public var period: Int           // seconds, default 30
    public var isSteam: Bool         // Steam Guard alphabet

    public init(secret: Data, algorithm: TOTPAlgorithm, digits: Int, period: Int, isSteam: Bool) {
        self.secret = secret
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.isSteam = isSteam
    }
}

/// Errors raised while parsing a TOTP secret/URI.
public enum TOTPError: Error, Equatable {
    case invalidSecret
    case invalidURI
}

public enum TOTP {
    /// Parse a TOTP secret stored in any of the forms Bitwarden accepts in `login.totp`:
    /// - a raw Base32 secret (`GEZD...`),
    /// - an `otpauth://totp/Label?secret=...&algorithm=...&digits=...&period=...` URI,
    /// - a Steam secret (`steam://<base32>`).
    ///
    /// Defaults: SHA-1, 6 digits, 30-second period. Steam forces a 5-character code.
    /// - Throws: `TOTPError.invalidURI` for a malformed `otpauth`/`steam` URI,
    ///   `TOTPError.invalidSecret` when the Base32 secret cannot be decoded.
    public static func configuration(from string: String) throws -> TOTPConfiguration {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = trimmed.lowercased()

        if lower.hasPrefix("steam://") {
            let raw = String(trimmed.dropFirst("steam://".count))
            guard let secret = Base32.decode(raw), !secret.isEmpty else { throw TOTPError.invalidURI }
            return TOTPConfiguration(secret: secret, algorithm: .sha1, digits: 5, period: 30, isSteam: true)
        }

        if lower.hasPrefix("otpauth://") {
            guard let components = URLComponents(string: trimmed) else { throw TOTPError.invalidURI }
            let items = components.queryItems ?? []
            func value(_ name: String) -> String? {
                items.first { $0.name.lowercased() == name }?.value
            }
            guard let secretString = value("secret"),
                  let secret = Base32.decode(secretString), !secret.isEmpty else {
                throw TOTPError.invalidURI
            }
            let algorithm: TOTPAlgorithm
            if let algo = value("algorithm") {
                guard let parsed = TOTPAlgorithm(rawValue: algo.uppercased()) else { throw TOTPError.invalidURI }
                algorithm = parsed
            } else {
                algorithm = .sha1
            }
            let digits = value("digits").flatMap { Int($0) } ?? 6
            let period = value("period").flatMap { Int($0) } ?? 30
            return TOTPConfiguration(secret: secret, algorithm: algorithm, digits: digits, period: period, isSteam: false)
        }

        // Otherwise treat the input as a raw Base32 secret.
        guard let secret = Base32.decode(trimmed), !secret.isEmpty else { throw TOTPError.invalidSecret }
        return TOTPConfiguration(secret: secret, algorithm: .sha1, digits: 6, period: 30, isSteam: false)
    }

    /// The code at a given instant (use a fixed `Date` in tests for determinism).
    public static func code(for config: TOTPConfiguration, at date: Date) -> String {
        let counter = UInt64(max(0, Int(date.timeIntervalSince1970) / config.period))
        let digest = hmac(counter: counter, key: config.secret, algorithm: config.algorithm)
        let offset = Int(digest[digest.count - 1] & 0x0f)
        let binary = (UInt32(digest[offset] & 0x7f) << 24)
            | (UInt32(digest[offset + 1]) << 16)
            | (UInt32(digest[offset + 2]) << 8)
            | UInt32(digest[offset + 3])
        if config.isSteam { return steamEncode(binary) }
        let mod = UInt32(pow(10.0, Double(config.digits)))
        return String(binary % mod).leftPadded(to: config.digits, with: "0")
    }

    /// Seconds remaining in the current period at `date`.
    public static func secondsRemaining(for config: TOTPConfiguration, at date: Date) -> Int {
        config.period - (Int(date.timeIntervalSince1970) % config.period)
    }

    private static func hmac(counter: UInt64, key: Data, algorithm: TOTPAlgorithm) -> [UInt8] {
        var c = counter.bigEndian
        let msg = withUnsafeBytes(of: &c) { Data($0) }
        let k = SymmetricKey(data: key)
        switch algorithm {
        // `Insecure.SHA1` is the correct CryptoKit type for TOTP's SHA-1.
        // RFC 6238 / HOTP mandate HMAC-SHA1; the "Insecure" label refers to
        // SHA-1's collision weakness, which is irrelevant to keyed HMAC-OTP.
        case .sha1:   return Array(HMAC<Insecure.SHA1>.authenticationCode(for: msg, using: k))
        case .sha256: return Array(HMAC<SHA256>.authenticationCode(for: msg, using: k))
        case .sha512: return Array(HMAC<SHA512>.authenticationCode(for: msg, using: k))
        }
    }

    private static let steamAlphabet = Array("23456789BCDFGHJKMNPQRTVWXY")
    private static func steamEncode(_ binary: UInt32) -> String {
        var v = binary
        var s = ""
        for _ in 0..<5 {
            s.append(steamAlphabet[Int(v % UInt32(steamAlphabet.count))])
            v /= UInt32(steamAlphabet.count)
        }
        return s
    }
}

private extension String {
    func leftPadded(to n: Int, with c: Character) -> String {
        count >= n ? self : String(repeating: c, count: n - count) + self
    }
}
