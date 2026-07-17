import Foundation
import AppShared
import VaultModels
import CryptoCore

/// URLSession async/await client for the Bitwarden/Vaultwarden REST API.
///
/// Two base paths are used: `/identity/*` for auth (`prelogin`, `token`, `refresh`)
/// and `/api/*` for the vault. The non-`/api` health route `/alive` is hit directly
/// on the base URL.
///
/// ## Design / testability
/// `init` injects the `URLSession`, so tests pass a session configured with a
/// custom `URLProtocol` that returns canned responses and captures the outgoing
/// request (method/path/headers/body). All request building is funneled through
/// `send(...)`, so header injection and error mapping are uniform and asserted in
/// one place.
///
/// ## Auth token
/// The access token for `/api/*` calls is held on the actor (`accessToken`) and
/// injected as `Authorization: Bearer`. The auth layer sets it via
/// `setAccessToken(_:)` after a successful `token`/`refresh`. This keeps the
/// `/api/*` method signatures clean while remaining explicit and testable (a test
/// can set the token, call `sync`, and assert the captured `Authorization` header).
public actor APIClient {
    private var environment: ServerEnvironment
    private let session: URLSession
    private let device: DeviceMetadata
    private let clientVersion: String

    /// Bearer token for `/api/*` requests; `nil` until login/refresh succeeds.
    private var accessToken: String?
    /// Canonical account id whose server + bearer are currently installed.
    private var activeAccountID: String?
    /// Unique owner of the current authentication incarnation. Account id alone cannot
    /// distinguish logout(A-old) from a newer login(A-new).
    private var activeAuthenticationContextID: UUID?
    /// Monotonically changes whenever the server/account/bearer context changes.
    /// A scoped request captures this value before suspension and validates it again
    /// after the response, preventing an A -> B -> A switch from reviving stale work.
    private var accountLeaseGeneration: UInt64 = 0
    /// Orders refresh-token grants without invalidating ordinary same-account vault
    /// requests when a bearer rotates.
    private var refreshAttemptGeneration: UInt64 = 0

    private struct AccountLease: Sendable, Equatable {
        let accountID: String
        let generation: UInt64
    }

    /// Decoder shared with VaultModels (case-insensitive, ISO-8601 w/ fractional seconds).
    private let decoder = VaultModels.VaultJSON.decoder()

    public init(environment: ServerEnvironment,
                session: URLSession = .shared,
                device: DeviceMetadata,
                clientVersion: String) {
        self.environment = environment
        self.session = session
        self.device = device
        self.clientVersion = clientVersion
    }

    /// Applies the server selected by the user before an authentication attempt.
    ///
    /// A bearer token is scoped to the server that issued it. Clear any existing token
    /// whenever an environment is applied so a subsequent request can never send a token
    /// from the previous server (this also makes a fresh login to the same server start
    /// from a clean authentication context).
    public func setEnvironment(_ environment: ServerEnvironment) {
        self.environment = environment
        accessToken = nil
        activeAccountID = nil
        activeAuthenticationContextID = nil
        advanceAccountLease()
        refreshAttemptGeneration &+= 1
    }

    /// Bind (or revoke) the account lease required by scoped vault requests.
    public func setAccountID(_ accountID: String?) {
        activeAccountID = accountID
        activeAuthenticationContextID = nil
        advanceAccountLease()
        refreshAttemptGeneration &+= 1
    }

    /// Bind the account lease to a unique repository authentication incarnation.
    public func bindAccount(_ accountID: String, contextID: UUID) {
        activeAccountID = accountID
        activeAuthenticationContextID = contextID
        advanceAccountLease()
        refreshAttemptGeneration &+= 1
    }

    /// Sets (or clears) the bearer token used for `/api/*` calls. Call after a
    /// successful `token`/`refresh`, or pass `nil` on logout.
    public func setAccessToken(_ token: String?) {
        self.accessToken = token
        refreshAttemptGeneration &+= 1
    }

    /// Install a bearer only if this account still owns the API environment.
    public func setAccessToken(_ token: String?, for accountID: String) throws {
        try requireAccount(accountID)
        accessToken = token
        refreshAttemptGeneration &+= 1
    }

    /// Revoke an account's bearer lease without disturbing a newer authentication
    /// context. In particular, an old logout that resumes after an A -> B transition
    /// becomes a no-op instead of clearing B's bearer/account binding.
    public func clearAccountContext(accountID: String, contextID: UUID) {
        guard activeAccountID == accountID,
              activeAuthenticationContextID == contextID else { return }
        accessToken = nil
        activeAccountID = nil
        activeAuthenticationContextID = nil
        advanceAccountLease()
        refreshAttemptGeneration &+= 1
    }

    /// The currently held access token, if any (exposed for the auth layer/tests).
    public func currentAccessToken() -> String? { accessToken }

    private func requireAccount(_ accountID: String) throws {
        guard activeAccountID == accountID else {
            throw NetworkingError.accountContextChanged
        }
    }

    private func accountLease(for accountID: String) throws -> AccountLease {
        try requireAccount(accountID)
        return AccountLease(accountID: accountID, generation: accountLeaseGeneration)
    }

    private func requireAccountLease(_ lease: AccountLease) throws {
        guard activeAccountID == lease.accountID,
              accountLeaseGeneration == lease.generation else {
            throw NetworkingError.accountContextChanged
        }
    }

    private func advanceAccountLease() {
        accountLeaseGeneration &+= 1
    }

    // MARK: - Identity (auth)

    /// `POST /identity/accounts/prelogin` with body `{"email": ...}`.
    /// Returns the server-driven KDF parameters. PBKDF2-only enforcement (kdf != 0
    /// rejection) is the auth layer's job, not this client's.
    public func prelogin(email: String) async throws -> PreloginResponse {
        try await prelogin(email: email, server: environment)
    }

    /// Server-bound prelogin used by the repository's reentrant login flow. Unlike the
    /// convenience overload, this never consults mutable shared environment state.
    public func prelogin(email: String,
                         server: ServerEnvironment) async throws -> PreloginResponse {
        let url = server.identityURL(path: "accounts/prelogin")
        var request = baseRequest(url: url, method: "POST")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: ["email": email])
        return try await sendDecoding(request, as: PreloginResponse.self)
    }

    /// `POST /identity/connect/token` (form-encoded password grant).
    ///
    /// On the first attempt `twoFactor` is `nil`. If the server replies 400 with a
    /// body containing `TwoFactorProviders2`, this returns `.twoFactorRequired`;
    /// the caller then retries with a populated `TwoFactorPayload`.
    public func token(email: String,
                      passwordHash: String,
                      twoFactor: TwoFactorPayload? = nil) async throws -> TokenResult {
        try await token(email: email, passwordHash: passwordHash, twoFactor: twoFactor,
                        server: environment)
    }

    /// Ask Vaultwarden/Bitwarden to issue an Email-2FA login code. This endpoint is
    /// unauthenticated but proves the master-password hash from the pending login.
    public func sendEmailLoginCode(
        email: String,
        masterPasswordHash: String,
        server: ServerEnvironment
    ) async throws {
        var request = baseRequest(
            url: server.apiURL(path: "two-factor/send-email-login"),
            method: "POST"
        )
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "email": email,
            "masterPasswordHash": masterPasswordHash,
            "deviceIdentifier": device.identifier,
        ])
        _ = try await perform(request)
    }

    /// Server-bound password grant used by an authentication attempt. Keeping the server
    /// in the call prevents another reentrant login from redirecting these credentials.
    public func token(email: String,
                      passwordHash: String,
                      twoFactor: TwoFactorPayload? = nil,
                      server: ServerEnvironment) async throws -> TokenResult {
        var fields: [(String, String)] = [
            ("grant_type", "password"),
            ("username", email),
            ("password", passwordHash),
            ("scope", "api offline_access"),
            ("client_id", Self.clientID),
            ("deviceType", String(device.type)),
            ("deviceIdentifier", device.identifier),
            ("deviceName", device.name),
        ]
        if let twoFactor {
            fields.append(("twoFactorToken", twoFactor.token))
            fields.append(("twoFactorProvider", String(twoFactor.provider.rawValue)))
            fields.append(("twoFactorRemember", twoFactor.remember ? "1" : "0"))
        }

        let request = formRequest(url: server.identityURL(path: "connect/token"), fields: fields)

        do {
            let (data, _) = try await perform(request)
            let token = try decode(TokenResponse.self, from: data)
            return .success(token)
        } catch let NetworkingError.http(status, body) where status == 400 {
            // A 400 whose body carries TwoFactorProviders2 is the 2FA challenge,
            // not a real error. Anything else (bad credentials, etc.) re-throws.
            if let data = body.data(using: .utf8),
               let providers = TwoFactorProviders(errorResponseData: data) {
                return .twoFactorRequired(providers)
            }
            throw NetworkingError.http(status: status, body: body)
        }
    }

    /// `POST /identity/connect/token` (refresh grant). On failure the caller must
    /// fall back to a full re-login.
    public func refresh(refreshToken: String) async throws -> TokenResponse {
        try await refresh(refreshToken: refreshToken, server: environment)
    }

    /// Server-bound refresh grant. A stale repository operation can therefore fail its
    /// account lease without ever disclosing one server's refresh token to another.
    public func refresh(refreshToken: String,
                        server: ServerEnvironment) async throws -> TokenResponse {
        let fields: [(String, String)] = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refreshToken),
            ("client_id", Self.clientID),
        ]
        let request = formRequest(url: server.identityURL(path: "connect/token"), fields: fields)
        return try await sendDecoding(request, as: TokenResponse.self)
    }

    /// Refresh and install a bearer under one account lease. The generation captured before
    /// sending must still be current after the response, so an A -> B -> A switch cannot let
    /// an old refresh overwrite the newly authenticated A bearer.
    public func refresh(refreshToken: String, server: ServerEnvironment,
                        accountID: String) async throws -> TokenResponse {
        let lease = try accountLease(for: accountID)
        refreshAttemptGeneration &+= 1
        let refreshAttempt = refreshAttemptGeneration
        let fields: [(String, String)] = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refreshToken),
            ("client_id", Self.clientID),
        ]
        let request = formRequest(url: server.identityURL(path: "connect/token"), fields: fields)
        let response = try await sendDecoding(request, as: TokenResponse.self)
        try requireAccountLease(lease)
        guard refreshAttemptGeneration == refreshAttempt else {
            throw NetworkingError.accountContextChanged
        }
        accessToken = response.accessToken
        return response
    }

    // MARK: - Vault (api)

    /// `GET /api/sync`. `excludeDomains=true` skips the equivalent-domains payload.
    public func sync(excludeDomains: Bool = true) async throws -> SyncResponse {
        var components = URLComponents(url: environment.apiURL(path: "sync"),
                                       resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "excludeDomains",
                                              value: excludeDomains ? "true" : "false")]
        let request = authedRequest(url: components.url!, method: "GET")
        return try await sendDecoding(request, as: SyncResponse.self)
    }

    public func sync(accountID: String, excludeDomains: Bool) async throws -> SyncResponse {
        let lease = try accountLease(for: accountID)
        var components = URLComponents(url: environment.apiURL(path: "sync"),
                                       resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "excludeDomains",
                                              value: excludeDomains ? "true" : "false")]
        let request = authedRequest(url: components.url!, method: "GET")
        let response = try await sendDecoding(request, as: SyncResponse.self)
        try requireAccountLease(lease)
        return response
    }

    /// `POST /api/ciphers` — create a personal-vault cipher.
    public func createCipher(_ req: CipherRequest) async throws -> CipherResponse {
        var request = authedRequest(url: environment.apiURL(path: "ciphers"), method: "POST")
        try attachJSONBody(&request, req)
        return try await sendDecoding(request, as: CipherResponse.self)
    }

    public func createCipher(accountID: String, _ req: CipherRequest) async throws -> CipherResponse {
        let lease = try accountLease(for: accountID)
        var request = authedRequest(url: environment.apiURL(path: "ciphers"), method: "POST")
        try attachJSONBody(&request, req)
        let response = try await sendDecoding(request, as: CipherResponse.self)
        try requireAccountLease(lease)
        return response
    }

    /// `PUT /api/ciphers/{id}` — update a cipher.
    public func updateCipher(id: String, _ req: CipherRequest) async throws -> CipherResponse {
        var request = authedRequest(url: environment.apiURL(path: "ciphers/\(id)"), method: "PUT")
        try attachJSONBody(&request, req)
        return try await sendDecoding(request, as: CipherResponse.self)
    }

    public func updateCipher(accountID: String, id: String,
                             _ req: CipherRequest) async throws -> CipherResponse {
        let lease = try accountLease(for: accountID)
        var request = authedRequest(url: environment.apiURL(path: "ciphers/\(id)"), method: "PUT")
        try attachJSONBody(&request, req)
        let response = try await sendDecoding(request, as: CipherResponse.self)
        try requireAccountLease(lease)
        return response
    }

    /// `DELETE /api/ciphers/{id}` — hard-delete a cipher.
    public func deleteCipher(id: String) async throws {
        let request = authedRequest(url: environment.apiURL(path: "ciphers/\(id)"), method: "DELETE")
        _ = try await perform(request)
    }

    public func deleteCipher(accountID: String, id: String) async throws {
        let lease = try accountLease(for: accountID)
        let request = authedRequest(url: environment.apiURL(path: "ciphers/\(id)"), method: "DELETE")
        _ = try await perform(request)
        try requireAccountLease(lease)
    }

    /// `GET /api/folders` — returns the user's folders (Bitwarden wraps them in
    /// `{ "data": [...] }`; Vaultwarden returns the same shape).
    public func folders() async throws -> [FolderResponse] {
        let request = authedRequest(url: environment.apiURL(path: "folders"), method: "GET")
        return try await sendDecoding(request, as: ListResponse<FolderResponse>.self).data
    }

    public func folders(accountID: String) async throws -> [FolderResponse] {
        let lease = try accountLease(for: accountID)
        let request = authedRequest(url: environment.apiURL(path: "folders"), method: "GET")
        let response = try await sendDecoding(request, as: ListResponse<FolderResponse>.self)
        try requireAccountLease(lease)
        return response.data
    }

    /// `POST /api/folders` — create a folder.
    public func createFolder(_ req: FolderRequest) async throws -> FolderResponse {
        var request = authedRequest(url: environment.apiURL(path: "folders"), method: "POST")
        try attachJSONBody(&request, req)
        return try await sendDecoding(request, as: FolderResponse.self)
    }

    /// `PUT /api/folders/{id}` — rename a folder.
    public func updateFolder(id: String, _ req: FolderRequest) async throws -> FolderResponse {
        var request = authedRequest(url: environment.apiURL(path: "folders/\(id)"), method: "PUT")
        try attachJSONBody(&request, req)
        return try await sendDecoding(request, as: FolderResponse.self)
    }

    /// `DELETE /api/folders/{id}` — delete a folder.
    public func deleteFolder(id: String) async throws {
        let request = authedRequest(url: environment.apiURL(path: "folders/\(id)"), method: "DELETE")
        _ = try await perform(request)
    }

    // MARK: - Attachments (v2)

    /// Attachment upload step 1: `POST /api/ciphers/{id}/attachment/v2` with body
    /// `{key, fileName, fileSize}`. Returns the `attachmentId` and the `url` to
    /// upload the encrypted blob to (step 2 is `uploadAttachment`).
    public func attachmentUploadURL(cipherID: String,
                                    _ req: AttachmentRequest) async throws -> AttachmentUploadResponse {
        var request = authedRequest(url: environment.apiURL(path: "ciphers/\(cipherID)/attachment/v2"),
                                    method: "POST")
        try attachJSONBody(&request, req)
        return try await sendDecoding(request, as: AttachmentUploadResponse.self)
    }

    /// Attachment upload step 2: upload the encrypted blob.
    ///
    /// For `fileUploadType == .direct` the blob is POSTed as `multipart/form-data`
    /// (field name `data`) to `/api/ciphers/{id}/attachment/{attachmentId}`; the
    /// caller passes that URL (from step 1's response, or built from the ids). For
    /// Azure the same blob is PUT directly to the SAS `url`.
    ///
    /// Here we implement the direct multipart path against the given `url` (this is
    /// the self-hosted Vaultwarden case). The bearer token is attached for the
    /// direct case; Azure SAS URLs already carry their own auth in the query.
    public func uploadAttachment(to url: URL,
                                 cipherID: String,
                                 attachmentID: String,
                                 encryptedData: Data) async throws {
        let isLocal = url.host == environment.apiBase.host
        var request: URLRequest
        if isLocal {
            request = authedRequest(url: url, method: "POST")
            let boundary = "Boundary-\(UUID().uuidString)"
            request.setValue("multipart/form-data; boundary=\(boundary)",
                             forHTTPHeaderField: "Content-Type")
            request.httpBody = multipartBody(boundary: boundary,
                                             fieldName: "data",
                                             fileName: attachmentID,
                                             data: encryptedData)
        } else {
            // Azure SAS upload: PUT the raw blob; the SAS token in the URL authorizes it.
            request = baseRequest(url: url, method: "PUT")
            request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
            request.setValue("BlockBlob", forHTTPHeaderField: "x-ms-blob-type")
            request.httpBody = encryptedData
        }
        _ = try await perform(request)
    }

    // MARK: - Misc

    /// `GET /api/config` — server version/capabilities. No auth required.
    public func config() async throws -> ServerConfig {
        let request = baseRequest(url: environment.apiURL(path: "config"), method: "GET")
        return try await sendDecoding(request, as: ServerConfig.self)
    }

    /// `GET /alive` — reachability probe. Returns `true` on a 2xx response.
    /// Transport failures map to `false` rather than throwing, since this is a probe.
    public func alive() async throws -> Bool {
        let request = baseRequest(url: environment.aliveURL, method: "GET")
        do {
            _ = try await perform(request)
            return true
        } catch NetworkingError.transport, NetworkingError.serverUnreachable {
            return false
        }
    }

    /// `POST /api/devices/identifier/{id}/token` — register a push token.
    ///
    /// NO-OP for self-hosted Vaultwarden: VW has no APNs relay (`pushTechnology = 0`)
    /// and ignores `devicePushToken`, so we deliberately do nothing here. The client
    /// uses polling + background refresh instead (see SyncEngine). Kept as a method
    /// so the call site is explicit and a future cloud target can fill it in.
    public func registerDevicePushToken(_ token: String) async throws {
        // Intentionally no network call — see doc comment.
        _ = token
    }

    // MARK: - Request building

    /// OAuth `client_id`. Bitwarden mobile clients send `mobile`.
    static let clientID = "mobile"

    /// Builds a request with the standard Bitwarden client headers but no auth.
    private func baseRequest(url: URL, method: String) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue(String(device.type), forHTTPHeaderField: "Device-Type")
        request.setValue("mobile", forHTTPHeaderField: "Bitwarden-Client-Name")
        request.setValue(clientVersion, forHTTPHeaderField: "Bitwarden-Client-Version")
        request.setValue(device.identifier, forHTTPHeaderField: "Device-Identifier")
        request.setValue(device.name, forHTTPHeaderField: "Device-Name")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return request
    }

    /// Builds an `/api/*` request with the bearer token attached.
    private func authedRequest(url: URL, method: String) -> URLRequest {
        var request = baseRequest(url: url, method: method)
        if let accessToken {
            request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        }
        return request
    }

    /// Builds a form-urlencoded request (used for the token endpoint).
    private func formRequest(url: URL, fields: [(String, String)]) -> URLRequest {
        var request = baseRequest(url: url, method: "POST")
        request.setValue("application/x-www-form-urlencoded; charset=utf-8",
                         forHTTPHeaderField: "Content-Type")
        request.httpBody = Self.formEncode(fields).data(using: .utf8)
        return request
    }

    /// JSON-encodes an `Encodable` body and sets the content-type.
    private func attachJSONBody<T: Encodable>(_ request: inout URLRequest, _ body: T) throws {
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        do {
            request.httpBody = try encoder.encode(body)
        } catch {
            throw NetworkingError.decoding("request encode: \(error)")
        }
    }

    // MARK: - Transport

    /// Performs the request, mapping transport/HTTP failures to `NetworkingError`.
    /// Returns the body data and the HTTP response for any 2xx status.
    @discardableResult
    private func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch let urlError as URLError {
            switch urlError.code {
            case .cannotFindHost, .cannotConnectToHost, .dnsLookupFailed,
                 .notConnectedToInternet, .timedOut:
                throw NetworkingError.serverUnreachable
            default:
                throw NetworkingError.transport(urlError.localizedDescription)
            }
        } catch {
            throw NetworkingError.transport(error.localizedDescription)
        }

        guard let http = response as? HTTPURLResponse else {
            throw NetworkingError.serverUnreachable
        }

        switch http.statusCode {
        case 200...299:
            return (data, http)
        case 401:
            throw NetworkingError.unauthorized
        default:
            let body = String(data: data, encoding: .utf8) ?? ""
            throw NetworkingError.http(status: http.statusCode, body: body)
        }
    }

    /// Performs the request and decodes the 2xx body as `T`.
    private func sendDecoding<T: Decodable>(_ request: URLRequest, as type: T.Type) async throws -> T {
        let (data, _) = try await perform(request)
        return try decode(T.self, from: data)
    }

    /// Decodes with the shared VaultModels decoder, mapping failures to `.decoding`.
    private func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            throw NetworkingError.decoding("\(error)")
        }
    }

    // MARK: - Encoding helpers

    /// Form-encodes key/value pairs. Both keys and values are
    /// percent-encoded with the application/x-www-form-urlencoded rules (space → `+`).
    static func formEncode(_ fields: [(String, String)]) -> String {
        fields.map { "\(formEscape($0.0))=\(formEscape($0.1))" }.joined(separator: "&")
    }

    private static func formEscape(_ s: String) -> String {
        // Unreserved set per RFC 3986; everything else percent-encoded. Space then
        // converted to `+` per form-urlencoding.
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._*")
        let escaped = s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
        return escaped.replacingOccurrences(of: "%20", with: "+")
    }

    /// Builds a minimal `multipart/form-data` body for a single file part.
    private func multipartBody(boundary: String, fieldName: String,
                               fileName: String, data: Data) -> Data {
        var body = Data()
        func append(_ s: String) { body.append(s.data(using: .utf8)!) }
        append("--\(boundary)\r\n")
        append("Content-Disposition: form-data; name=\"\(fieldName)\"; filename=\"\(fileName)\"\r\n")
        append("Content-Type: application/octet-stream\r\n\r\n")
        body.append(data)
        append("\r\n--\(boundary)--\r\n")
        return body
    }
}

/// Bitwarden list-endpoint envelope: `{ "object": "list", "data": [...] }`.
/// `continuationToken` is present on some paged endpoints; unused for folders.
struct ListResponse<Element: Decodable & Sendable>: Decodable, Sendable {
    let data: [Element]

    enum CodingKeys: String, CodingKey { case data }
}
