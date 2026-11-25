import Foundation

/// Information sent to AuthenticationServices. Report only the web origin, not an
/// item URL's path, user information, query, or fragment. Path-dependent rules
/// are left to explicit picker selection rather than broadened to a full site.
package enum AutoFillWebsiteIdentity {
    package static func value(for raw: String, match: Int?) -> String? {
        guard match == nil || match == 0 || match == 1 || match == 3,
              var parts = URLComponents(string: raw.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = parts.scheme?.lowercased(), scheme == "https" || scheme == "http",
              let host = parts.host?.lowercased(), !host.isEmpty,
              parts.user == nil, parts.password == nil else { return nil }
        if match == 3, !parts.percentEncodedPath.isEmpty || parts.query != nil || parts.fragment != nil { return nil }
        parts.scheme = scheme
        parts.host = host
        parts.path = ""
        parts.query = nil
        parts.fragment = nil
        return parts.url?.absoluteString
    }
}
