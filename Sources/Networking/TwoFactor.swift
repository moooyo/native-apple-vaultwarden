import Foundation
import VaultModels

/// The two-factor providers a server offers when a password grant is rejected for
/// 2FA. Vaultwarden/Bitwarden return a JSON object whose keys are the integer
/// provider IDs (as strings) mapping to provider-specific metadata, e.g.:
///
/// ```json
/// { "TwoFactorProviders": ["0"],
///   "TwoFactorProviders2": { "0": {}, "1": { "Email": "j***@example.com" } } }
/// ```
///
/// We surface the available provider IDs (parsed into the `TwoFactorProvider` enum
/// where known) and keep the raw metadata so callers can show, e.g., the masked
/// email for the Email provider.
public struct TwoFactorProviders: Sendable, Equatable {
    /// The provider IDs the server offered, in ascending numeric order.
    public let providerIDs: [Int]
    /// Raw per-provider metadata keyed by provider ID, as decoded JSON.
    public let raw: [Int: [String: TwoFactorMetadataValue]]

    public init(providerIDs: [Int], raw: [Int: [String: TwoFactorMetadataValue]]) {
        self.providerIDs = providerIDs
        self.raw = raw
    }

    /// The offered providers parsed into the known `TwoFactorProvider` enum
    /// (unknown IDs are dropped from this convenience view).
    public var providers: [TwoFactorProvider] {
        providerIDs.compactMap(TwoFactorProvider.init(rawValue:))
    }

    /// Parses the `TwoFactorProviders2` object out of a token-error response body.
    /// Returns `nil` if the body has no such field (i.e. it is not a 2FA challenge).
    public init?(errorResponseData data: Data) {
        guard
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }

        // Vaultwarden uses PascalCase; tolerate camelCase too. The rich object is
        // `TwoFactorProviders2`; fall back to the legacy `TwoFactorProviders` array.
        let providers2 = (object["TwoFactorProviders2"] ?? object["twoFactorProviders2"])
            as? [String: Any]

        if let providers2 {
            var raw: [Int: [String: TwoFactorMetadataValue]] = [:]
            var ids: [Int] = []
            for (key, value) in providers2 {
                guard let id = Int(key) else { continue }
                ids.append(id)
                if let dict = value as? [String: Any] {
                    raw[id] = dict.mapValues(TwoFactorMetadataValue.init(any:))
                } else {
                    raw[id] = [:]
                }
            }
            guard !ids.isEmpty else { return nil }
            self.init(providerIDs: ids.sorted(), raw: raw)
            return
        }

        // Legacy array-of-string-ids form.
        if let array = (object["TwoFactorProviders"] ?? object["twoFactorProviders"]) as? [Any] {
            let ids = array.compactMap { element -> Int? in
                if let i = element as? Int { return i }
                if let s = element as? String { return Int(s) }
                return nil
            }
            guard !ids.isEmpty else { return nil }
            self.init(providerIDs: ids.sorted(), raw: [:])
            return
        }

        return nil
    }
}

/// A loosely-typed JSON scalar for 2FA provider metadata (e.g. the masked email
/// string for the Email provider, or a nonce). Kept `Equatable`/`Sendable` so
/// `TwoFactorProviders` is comparable in tests.
public enum TwoFactorMetadataValue: Sendable, Equatable {
    case string(String)
    case int(Int)
    case bool(Bool)
    case null
    case other

    init(any value: Any) {
        switch value {
        case let s as String: self = .string(s)
        case let b as Bool: self = .bool(b)
        case let i as Int: self = .int(i)
        case is NSNull: self = .null
        default: self = .other
        }
    }
}

/// Known Bitwarden two-factor provider types. Raw values are the integer IDs sent
/// as `twoFactorProvider` on the retry.
public enum TwoFactorProvider: Int, Sendable, Equatable, CaseIterable {
    case authenticator = 0
    case email = 1
    case duo = 2
    case yubikey = 3
    case u2f = 4
    case remember = 5
    case organizationDuo = 6
    case webAuthn = 7
}

/// The fields added to a token-grant form on a 2FA retry.
public struct TwoFactorPayload: Sendable, Equatable {
    /// The provider type being answered.
    public let provider: TwoFactorProvider
    /// The user-supplied code / token (e.g. TOTP code, emailed code).
    public let token: String
    /// Whether to remember this device so 2FA isn't required next time.
    public let remember: Bool

    public init(provider: TwoFactorProvider, token: String, remember: Bool = false) {
        self.provider = provider
        self.token = token
        self.remember = remember
    }
}

/// The outcome of a token-grant request.
public enum TokenResult: Sendable {
    /// Authentication succeeded.
    case success(TokenResponse)
    /// The server requires a second factor; retry `token` with a `TwoFactorPayload`.
    case twoFactorRequired(TwoFactorProviders)
}
