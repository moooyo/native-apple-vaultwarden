import Foundation

/// Errors surfaced by `APIClient`. `http` carries the raw status and (decoded, if
/// possible) response body so the caller can show or log a server message;
/// `unauthorized` (401) is split out as its own case so the auth/refresh layer can
/// special-case re-login without string-matching on a status code.
public enum NetworkingError: Error, Equatable, Sendable {
    /// Underlying URLSession transport failure (DNS, TLS, timeout, offline …).
    /// The associated string is `localizedDescription` so the case stays `Equatable`.
    case transport(String)
    /// A non-2xx HTTP response (other than 401). Carries status code and body text.
    case http(status: Int, body: String)
    /// Response decoding failed. The associated string describes the decode error.
    case decoding(String)
    /// HTTP 401 — the access/refresh token is invalid or expired.
    case unauthorized
    /// The response was not an `HTTPURLResponse`, or the host could not be reached
    /// in a way that maps to "server unreachable".
    case serverUnreachable
}
