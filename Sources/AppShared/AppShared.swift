import Foundation
import CryptoKit

/// AppShared — cross-target constants and small value types so the main app and the
/// AutoFill extension agree on identifiers (App Group, shared Keychain access group,
/// default server). No dependencies; safe to build/run headless (reading constants
/// needs no entitlements). See docs/superpowers/plans §A.
public enum AppShared {
    /// App Group identifier shared by app + extension. Placeholder — set to the real group.
    public static let appGroupID = "group.dev.moooyo.tessera"

    /// Shared Keychain access group. Xcode expands `$(AppIdentifierPrefix)` into the
    /// custom Info.plist value for every signed app/extension target.
    public static var keychainAccessGroup: String {
        Bundle.main.object(forInfoDictionaryKey: "OpenVaultKeychainAccessGroup") as? String
            ?? "dev.moooyo.tessera.shared"
    }

    /// Shared generic-password item names. Keeping these in this lightweight module
    /// prevents the app and credential-provider extension from drifting apart.
    public enum KeychainAccount {
        public static let databasePassphrase = "tessera.db-passphrase"
        public static let activeAccountID = "tessera.active-account-id"
        /// Random incarnation nonce. Rotated on restore/lock/login so an already-unlocked
        /// extension process cannot survive an A -> B -> A account/session transition.
        public static let activeSessionID = "tessera.active-session-id"
        public static let biometricAccountID = "tessera.biometric-account-id"
        /// Legacy single-account names retained only for one-way cleanup/migration.
        public static let legacyRefreshToken = "tessera.refresh-token"
        public static let legacyLocalAuthHash = "tessera.local-auth-hash"
        public static let passkeyRegistrationPrefix = "tessera.passkey-registration."

        public static func refreshToken(accountID: String) -> String {
            "tessera.refresh-token|\(accountID)"
        }

        public static func localAuthHash(accountID: String) -> String {
            "tessera.local-auth-hash|\(accountID)"
        }
    }

    /// Default server URL. Empty → the user must enter a self-hosted Vaultwarden URL.
    public static let defaultServerURL = ""
}

/// Opaque, account-bound `ASCredentialIdentity.recordIdentifier` codec.
///
/// Raw cipher UUIDs are not globally unique once cloned servers coexist in the composite-key
/// cache. The system identity must therefore carry account provenance, but it should not expose
/// the server URL/email account id in plaintext. A SHA-256 account tag plus base64url cipher id
/// lets the extension validate against its active account before any row lookup.
public enum CredentialRecordIdentifier {
    public enum Kind: String, Sendable {
        case password
        case oneTimeCode
        case passkey
    }

    private static let version = "v3"

    public static func encode(
        accountID: String,
        cipherID: String,
        kind: Kind,
        serviceIdentifier: String,
        user: String
    ) -> String {
        let accountHash = Data(SHA256.hash(data: Data(accountID.utf8)))
        let serviceHash = Data(SHA256.hash(data: Data(serviceIdentifier.utf8)))
        let userHash = Data(SHA256.hash(data: Data(user.utf8)))
        return "\(version).\(base64URL(accountHash)).\(kind.rawValue)."
            + "\(base64URL(serviceHash)).\(base64URL(userHash))."
            + base64URL(Data(cipherID.utf8))
    }

    public static func decode(
        _ value: String,
        expectedAccountID: String,
        expectedKind: Kind,
        expectedServiceIdentifier: String,
        expectedUser: String
    ) -> String? {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 6, parts[0] == Substring(version),
              let accountHash = decodeBase64URL(String(parts[1])),
              accountHash == Data(SHA256.hash(data: Data(expectedAccountID.utf8))),
              parts[2] == Substring(expectedKind.rawValue),
              let serviceHash = decodeBase64URL(String(parts[3])),
              serviceHash == Data(SHA256.hash(
                  data: Data(expectedServiceIdentifier.utf8)
              )),
              let userHash = decodeBase64URL(String(parts[4])),
              userHash == Data(SHA256.hash(data: Data(expectedUser.utf8))),
              let cipherData = decodeBase64URL(String(parts[5])),
              !cipherData.isEmpty,
              let cipherID = String(data: cipherData, encoding: .utf8),
              !cipherID.isEmpty else {
            return nil
        }
        return cipherID
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func decodeBase64URL(_ value: String) -> Data? {
        guard !value.isEmpty,
              value.utf8.allSatisfy({ byte in
                  (byte >= 65 && byte <= 90)
                      || (byte >= 97 && byte <= 122)
                      || (byte >= 48 && byte <= 57)
                      || byte == 45 || byte == 95
              }) else { return nil }
        let remainder = value.utf8.count % 4
        guard remainder != 1 else { return nil }
        var base64 = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: base64)
    }
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
