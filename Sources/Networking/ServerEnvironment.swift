import Foundation

/// Resolves the two base paths a Bitwarden/Vaultwarden deployment exposes:
/// `/identity/*` (authentication) and `/api/*` (vault), plus the non-`/api`
/// health route `/alive`.
///
/// A self-hosted Vaultwarden is reached at a single base URL (e.g.
/// `https://vault.example.com`) where identity lives at `<base>/identity` and the
/// vault API at `<base>/api`. Official Bitwarden (and some reverse-proxy setups)
/// can split identity and api onto separate hosts, so both can be overridden.
public struct ServerEnvironment: Sendable, Equatable {
    /// The user-entered base URL (e.g. `https://vault.example.com`).
    public var base: URL
    /// Optional override for the identity host. When `nil`, `identityBase` is
    /// derived as `base` + `/identity`.
    public var identityURL: URL?
    /// Optional override for the api host. When `nil`, `apiBase` is derived as
    /// `base` + `/api`.
    public var apiURL: URL?

    public init(base: URL, identityURL: URL? = nil, apiURL: URL? = nil) {
        self.base = base
        self.identityURL = identityURL
        self.apiURL = apiURL
    }

    /// Convenience initializer from a user-entered string. Trims whitespace and a
    /// trailing slash so `https://vault.example.com/` and `https://vault.example.com`
    /// resolve identically. Only absolute HTTP(S) URLs with a host are accepted;
    /// query/fragment components are rejected because they cannot be a stable API base.
    public init?(string: String) {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let normalized = trimmed.replacingOccurrences(of: #"/+$"#,
                                                       with: "",
                                                       options: .regularExpression)
        guard let url = URL(string: normalized),
              let scheme = url.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              url.host?.isEmpty == false,
              url.user == nil,
              url.password == nil,
              url.query == nil,
              url.fragment == nil else { return nil }
        self.init(base: url)
    }

    /// Base URL for identity (auth) endpoints. Defaults to `base/identity`.
    public var identityBase: URL {
        identityURL ?? base.appendingPathComponent("identity")
    }

    /// Base URL for vault api endpoints. Defaults to `base/api`.
    public var apiBase: URL {
        apiURL ?? base.appendingPathComponent("api")
    }

    /// Builds an identity URL from a path like `accounts/prelogin` (no leading slash).
    func identityURL(path: String) -> URL {
        identityBase.appendingPathComponent(path)
    }

    /// Builds an api URL from a path like `sync` (no leading slash).
    func apiURL(path: String) -> URL {
        apiBase.appendingPathComponent(path)
    }

    /// The Vaultwarden-specific health route. It lives at the deployment root
    /// (NOT under `/api`), so it is derived from `base`, not `apiBase`.
    var aliveURL: URL {
        base.appendingPathComponent("alive")
    }
}
