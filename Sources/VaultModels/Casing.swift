import Foundation

/// JSON coding helpers that make VaultModels decode both Vaultwarden (camelCase)
/// and official Bitwarden (PascalCase) payloads from the same model declarations.
///
/// The decoder lowercases every incoming key; models therefore declare
/// `CodingKeys` whose raw values are the **lowercased** form of the wire key
/// (e.g. `case revisionDate = "revisiondate"`, `case accessToken = "access_token"`).
///
/// ## CONTRACT for model authors (enforced only by tests):
/// - EVERY model's `CodingKeys` raw value MUST be the lowercased form of the wire
///   key. A camelCase raw value (e.g. `case fooBar` with no `= "foobar"`) will
///   silently fail to match the lowercased incoming key and decode as `nil` — no
///   error is thrown. Underscores are unaffected by lowercasing, so OAuth keys
///   like `access_token` stay `access_token`.
/// - Whenever you add a field, add a decode test that exercises BOTH a camelCase
///   and a PascalCase JSON variant for it. Without that test a mistyped CodingKey
///   silently decodes as nil and nothing catches it.
public enum VaultJSON {
    public static func decoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .custom { keys in
            let last = keys.last!
            return AnyCodingKey(stringValue: last.stringValue.lowercasedFirstScalarFold())
        }
        d.dateDecodingStrategy = .iso8601WithFractionalSeconds
        return d
    }

    /// WARNING: this encoder is for INTERNAL round-trip tests only — it is NOT
    /// server-shaped. It emits the deliberately-lowercased `CodingKeys` raw values
    /// (e.g. `"revisiondate"`, not `"revisionDate"`), and its ISO-8601 date strategy
    /// has no fractional-seconds option, so it drops sub-second precision. Do NOT
    /// use it to produce payloads sent to a Vaultwarden/Bitwarden server. M2 write
    /// paths will need a dedicated server-shaped encoder (proper key casing +
    /// fractional-seconds dates); that is intentionally out of scope here.
    public static func encoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        return e
    }
}

/// A type-erased `CodingKey` used by the case-insensitive decoding strategy.
public struct AnyCodingKey: CodingKey {
    public let stringValue: String
    public let intValue: Int?
    public init(stringValue: String) { self.stringValue = stringValue; self.intValue = nil }
    public init(intValue: Int) { self.stringValue = String(intValue); self.intValue = intValue }
}

extension String {
    /// Fold a JSON key to a canonical lowercased form for case-insensitive matching.
    func lowercasedFirstScalarFold() -> String { lowercased() }
}

extension JSONDecoder.DateDecodingStrategy {
    /// Bitwarden/Vaultwarden emit ISO-8601 with fractional seconds; tolerate both.
    static var iso8601WithFractionalSeconds: JSONDecoder.DateDecodingStrategy {
        .custom { decoder in
            let s = try decoder.singleValueContainer().decode(String.self)
            let withFrac = ISO8601DateFormatter()
            withFrac.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let d = withFrac.date(from: s) { return d }
            let plain = ISO8601DateFormatter()
            plain.formatOptions = [.withInternetDateTime]
            if let d = plain.date(from: s) { return d }
            throw DecodingError.dataCorruptedError(in: try decoder.singleValueContainer(),
                debugDescription: "Bad ISO-8601 date: \(s)")
        }
    }
}
