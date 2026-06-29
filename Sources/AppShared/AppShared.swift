import Foundation

/// AppShared — cross-target constants and small value types so the main app and the
/// AutoFill extension agree on identifiers (App Group, shared Keychain access group,
/// default server). No dependencies; safe to build/run headless (reading constants
/// needs no entitlements). See docs/superpowers/plans §A.
public enum AppShared {
    /// App Group identifier shared by app + extension. Placeholder — set to the real group.
    public static let appGroupID = "group.dev.moooyo.tessera"

    /// Shared Keychain access group. Placeholder — `<TEAMID>` is replaced with the real
    /// `$(AppIdentifierPrefix)` at signing time.
    public static let keychainAccessGroup = "TEAMID.dev.moooyo.tessera.shared"

    /// Default server URL. Empty → the user must enter a self-hosted Vaultwarden URL.
    public static let defaultServerURL = ""
}

/// Stable per-install device metadata sent to the server (mirrors Bitwarden `DeviceType`).
public struct DeviceMetadata: Sendable, Equatable {
    /// Bitwarden `DeviceType`: iOS = 1, MacOsDesktop = 7.
    public let type: Int
    /// Stable UUID persisted in App Group UserDefaults.
    public let identifier: String
    /// Human-readable device name.
    public let name: String

    public init(type: Int, identifier: String, name: String) {
        self.type = type
        self.identifier = identifier
        self.name = name
    }
}

extension DeviceMetadata {
    /// Bitwarden `DeviceType` raw values used by this client.
    public enum DeviceType {
        public static let iOS = 1
        public static let macOSDesktop = 7
    }
}

/// Auto-lock timeout options. Raw value is the timeout in seconds;
/// `immediately` (0) locks on backgrounding, `never` (-1) disables the timeout.
public enum AutoLockTimeout: Int, Sendable, CaseIterable {
    case immediately = 0
    case oneMinute = 60
    case fiveMinutes = 300
    case fifteenMinutes = 900
    case oneHour = 3600
    case never = -1
}

/// Log redaction so secrets are never written to logs. Anything that looks like a
/// secret (tokens, EncStrings, base64 key material) is collapsed to a placeholder.
public enum LogRedaction {
    private static let placeholder = "<redacted>"

    /// Returns a log-safe version of `s` with likely secrets redacted.
    /// Conservative by design: it would rather over-redact than leak a secret.
    public static func redact(_ s: String) -> String {
        var result = s

        // EncString wire format: "<type>.<base64...>" possibly with "|" separators.
        result = redact(result, matching: #"\b[0-9]\.[A-Za-z0-9+/=]{12,}(?:\|[A-Za-z0-9+/=]+)*"#)

        // Bearer tokens.
        result = redact(result, matching: #"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"#)

        // JWT-shaped tokens: three base64url segments separated by dots.
        result = redact(result, matching: #"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"#)

        // Long base64 / hex blobs (likely key material).
        result = redact(result, matching: #"\b[A-Za-z0-9+/]{40,}={0,2}"#)

        return result
    }

    private static func redact(_ input: String, matching pattern: String) -> String {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return input }
        let range = NSRange(input.startIndex..<input.endIndex, in: input)
        return regex.stringByReplacingMatches(in: input, range: range, withTemplate: placeholder)
    }
}
