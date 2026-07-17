import Foundation
import VaultModels
import Networking

/// The subset of the network API the auth flow depends on.
///
/// Declaring a protocol (rather than taking `Networking.APIClient` directly) gives the
/// auth logic a test seam: the unit tests inject an in-memory fake that returns canned
/// prelogin/token/refresh responses and records the access token set on it — without any
/// URLSession or live server.
///
/// `Networking.APIClient` is made to conform via an empty extension in this module (the
/// method signatures already match), so `Networking` itself stays untouched.
public protocol AuthAPI: Sendable {
    /// Select the deployment used by subsequent identity and vault requests.
    func setEnvironment(_ environment: ServerEnvironment) async
    /// `POST /identity/accounts/prelogin`.
    func prelogin(email: String) async throws -> PreloginResponse
    /// `POST /identity/connect/token` (password grant; optional 2FA payload).
    func token(email: String, passwordHash: String, twoFactor: TwoFactorPayload?) async throws -> TokenResult
    /// `POST /identity/connect/token` (refresh grant).
    func refresh(refreshToken: String) async throws -> TokenResponse
    /// Set (or clear) the bearer token used for `/api/*` calls.
    func setAccessToken(_ token: String?) async
}

/// Make the real `Networking.APIClient` satisfy `AuthAPI`. The signatures already match
/// (`setAccessToken` is non-async on the actor but satisfies the `async` requirement), so
/// the conformance is empty — declared here to keep `Networking` free of any
/// repository coupling.
extension APIClient: AuthAPI {}
