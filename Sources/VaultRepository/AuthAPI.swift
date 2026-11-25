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
    /// Apply the user-selected server before starting authentication. Implementations
    /// must clear any bearer token associated with the previous environment.
    func setEnvironment(_ environment: ServerEnvironment) async
    func setAccountID(_ accountID: String?) async
    /// Bind an account to one unique authentication incarnation (ABA guard).
    func bindAccount(_ accountID: String, contextID: UUID) async
    /// `POST /identity/accounts/prelogin`, explicitly bound to this attempt's server.
    func prelogin(email: String, server: ServerEnvironment) async throws -> PreloginResponse
    func requestPasswordHint(email: String, server: ServerEnvironment) async throws
    /// `POST /identity/connect/token` (password grant; optional 2FA payload).
    func token(email: String, passwordHash: String, twoFactor: TwoFactorPayload?,
               server: ServerEnvironment) async throws -> TokenResult
    func sendEmailLoginCode(email: String, masterPasswordHash: String,
                            server: ServerEnvironment) async throws
    func deviceLoginToken(email: String, accessCode: DeviceLoginAccessCode, requestID: UUID,
                          twoFactor: TwoFactorPayload?, server: ServerEnvironment) async throws -> TokenResult
    func sendDeviceLoginEmailCode(email: String, accessCode: DeviceLoginAccessCode,
                                  requestID: UUID, server: ServerEnvironment) async throws
    /// Refresh and install the bearer under the session's still-current account lease.
    func refresh(refreshToken: String, server: ServerEnvironment,
                 accountID: String, contextID: UUID?) async throws -> TokenResponse
    func refresh(refreshToken: String, server: ServerEnvironment, accountID: String,
                 contextID: UUID?, installAccessToken: Bool) async throws -> TokenResponse
    func hasUsableAccessToken(accountID: String, contextID: UUID) async throws -> Bool
    /// Install a bearer and its lifetime only in the matching authentication context.
    func installAccessToken(_ token: String, expiresIn: Int, for accountID: String, contextID: UUID) async throws
    /// Set or clear a bearer under the current authentication context.
    func setAccessToken(_ token: String?, for accountID: String, contextID: UUID) async throws
    /// Atomically revoke the bearer + account binding only when `accountID` still owns
    /// the API context. A superseded logout must not clear a newer account's session.
    func clearAccountContext(accountID: String, contextID: UUID) async
}

/// Make the real `Networking.APIClient` satisfy `AuthAPI`. The signatures already match
/// (`setAccessToken` is non-async on the actor but satisfies the `async` requirement), so
/// the conformance is empty — declared here to keep `Networking` free of any
/// repository coupling.
extension APIClient: AuthAPI {}

public extension AuthAPI {
    func deviceLoginToken(email: String, accessCode: DeviceLoginAccessCode, requestID: UUID,
                          twoFactor: TwoFactorPayload?, server: ServerEnvironment) async throws -> TokenResult {
        throw DeviceLoginError.requestUnavailable
    }

    func sendDeviceLoginEmailCode(email: String, accessCode: DeviceLoginAccessCode,
                                  requestID: UUID, server: ServerEnvironment) async throws {
        throw DeviceLoginError.requestUnavailable
    }
}
