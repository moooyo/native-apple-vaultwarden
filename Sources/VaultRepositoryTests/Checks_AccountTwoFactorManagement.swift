import AppShared
import CryptoKit
import Foundation
import KeyVault
import Networking
import VaultRepository
import os

func checkAccountTwoFactorManagement(_ runner: inout TestRunner) async {
    let server = ServerEnvironment(string: "https://factors.example.test/vault")!
    let root = "/vault/api/two-factor"
    let secret = String(repeating: "A", count: 32)
    let recovery = String(repeating: "B", count: 32)
    let address = "verification@example.test"
    let emailOff = #"{"email":{"enabled":false,"email":null},"userVerificationToken":"email-off"}"#
    let emailOn = #"{"email":{"enabled":true,"email":"verification@example.test"},"userVerificationToken":"email-on"}"#
    let authOff = """
        {"Authenticator":{"Enabled":false,"Key":"\(secret)"},"UserVerificationToken":"auth-off"}
        """
    let securityKey = #"{"webAuthn":{"enabled":true,"keys":[{"id":17,"name":"Key one","migrated":false}]},"userVerificationToken":"key-proof"}"#
    let releaseRecovery = DispatchSemaphore(value: 0)
    let keyChallenge = factorBase64URL(Data(repeating: 5, count: 32))
    let registrationKeyState = #"{"webAuthn":{"enabled":false,"keys":[]},"userVerificationToken":"register-proof"}"#
    let registeredKeyState = #"{"webAuthn":{"enabled":true,"keys":[{"id":1,"name":"New key","migrated":false}]},"userVerificationToken":"second-proof"}"#
    let registrationOptions = """
        {"options":{"status":"ok","errorMessage":"","rp":{"id":"factors.example.test","name":"Vaultwarden"},
          "user":{"id":"\(factorBase64URL(Data(repeating: 1, count: 16)))","name":"\(Fixtures.email)","displayName":"Fixture"},
          "challenge":"\(keyChallenge)","pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],
          "excludeCredentials":[],"authenticatorSelection":{"residentKey":"discouraged","requireResidentKey":false,
          "userVerification":"discouraged"},"attestation":"none","timeout":60000}}
        """
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [AccountTwoFactorFixture.self]
    let session = URLSession(configuration: configuration)
    defer { session.invalidateAndCancel(); AccountTwoFactorFixture.reset() }

    let device = DeviceMetadata(type: DeviceMetadata.DeviceType.iOS, identifier: "factor-test", name: "Factor fixture")
    let api = APIClient(environment: server, session: session, device: device, clientVersion: "1")
    AccountTwoFactorFixture.script([
        .init("POST", "/vault/identity/accounts/prelogin", "{\"kdf\":0,\"kdfIterations\":\(Fixtures.iterations)}"),
        .init("POST", "/vault/identity/connect/token", """
            {"access_token":"factor-bearer","expires_in":3600,"refresh_token":"refresh-1","token_type":"Bearer","Key":"\(Fixtures.protectedUserKeyWire())","Kdf":0}
            """),
        .init("GET", root, #"{"data":[{"type":7,"enabled":true},{"type":27,"enabled":false}],"object":"list","continuationToken":null}"#),
        .init("POST", root + "/get-recover", "{\"object\":\"twoFactorRecover\",\"code\":\"\(recovery)\"}"),
        .init("POST", root + "/get-recover", "{\"code\":\"\(recovery)\"}", status: 400),
        .init("POST", root + "/get-recover", #"{"object":"twoFactorRecover","code":null}"#),
        .init("POST", root + "/get-authenticator", authOff),
        .init("GET", root, #"{"data":[],"object":"list","continuationToken":null}"#),
        .init("PUT", root + "/authenticator", "{\"authenticator\":{\"enabled\":true,\"key\":\"\(secret)\"}}"),
        .init("POST", root + "/get-authenticator", """
            {"authenticator":{"enabled":true,"key":"\(secret)"},"userVerificationToken":"readback"}
            """),
        .init("POST", root + "/get-authenticator", """
            {"authenticator":{"enabled":true,"key":"\(secret)"},"userVerificationToken":"auth-on"}
            """),
        .init("DELETE", root + "/authenticator", ""),
        .init("GET", root, #"{"data":[{"type":7,"enabled":true}],"object":"list","continuationToken":null}"#),
        .init("POST", root + "/get-email", emailOn),
        .init("POST", root + "/get-email", emailOff),
        .init("POST", root + "/send-email", "{}"),
        .init("POST", root + "/get-email", emailOff),
        .init("PUT", root + "/email", "{}"),
        .init("POST", root + "/get-email", emailOn),
        .init("POST", root + "/get-email", emailOn),
        .init("DELETE", root + "/email", ""),
        .init("GET", root, #"{"data":[{"type":1,"enabled":true},{"type":7,"enabled":true}],"object":"list","continuationToken":null}"#),
        .init("POST", root + "/get-webauthn", securityKey),
        .init("POST", root + "/get-webauthn", securityKey.replacingOccurrences(of: "Key one", with: "Other key")),
        .init("POST", root + "/get-webauthn", securityKey),
        .init("DELETE", root + "/webauthn", #"{"webAuthn":{"enabled":false,"keys":[]}}"#),
        .init("POST", root + "/get-webauthn", registrationKeyState),
        .init("POST", root + "/get-webauthn-challenge", registrationOptions.replacingOccurrences(of: "\"alg\":-7", with: "\"alg\":-8")),
        .init("POST", root + "/get-webauthn", registrationKeyState),
        .init("POST", root + "/get-webauthn-challenge", registrationOptions),
        .init("POST", root + "/get-webauthn", registrationKeyState),
        .init("POST", root + "/get-webauthn-challenge", registrationOptions),
        .init("PUT", root + "/webauthn", #"{"webAuthn":{"enabled":true,"keys":[{"id":1,"name":"New key","migrated":false}]}}"#),
        .init("POST", root + "/get-webauthn", registeredKeyState),
        .init("POST", root + "/get-webauthn-challenge", registrationOptions.replacingOccurrences(
            of: #""excludeCredentials":[]"#, with: #""excludeCredentials":[{"type":"public-key","id":"AQMF"}]"#)),
        .init("POST", root + "/get-authenticator", authOff),
        .init("POST", root + "/get-recover", "{\"object\":\"twoFactorRecover\",\"code\":\"\(recovery)\"}", waitFor: releaseRecovery),
    ])

    do {
        let (store, directory) = try await Fixtures.freshStore()
        defer { Fixtures.cleanup(directory) }
        let auth = AuthRepository(api: api, keyVault: KeyVault(), keychain: makeFakeKeychain(),
                                  store: store, encryptor: UserKeyEncryptor())
        let management = AccountTwoFactorManagement(api: api, auth: auth)
        _ = try await auth.login(email: Fixtures.email, password: Fixtures.password, server: server)
        guard let lease = await management.unlockedSessionLease() else {
            runner.expectTrue(false, "2FA settings fixture unlocked"); return
        }
        let initialMethods = try await management.methods(for: lease)
        runner.expect(initialMethods.map(\.type), [7, 27], "2FA settings preserve known and unrecognized provider IDs")
        runner.expect(initialMethods.map(\.enabled), [true, false], "2FA settings use server status")

        let beforePasswordFailure = AccountTwoFactorFixture.calls.count
        await runner.expectThrowsErrorAsync(RepositoryError.authenticationFailed, "recovery requires the correct master password") {
            _ = try await management.revealRecoveryCode(for: lease, password: "wrong password")
        }
        runner.expect(AccountTwoFactorFixture.calls.count, beforePasswordFailure, "incorrect password never sends a protected request")
        runner.expectTrue(try await management.revealRecoveryCode(for: lease, password: Fixtures.password) == recovery,
                          "recovery reveals the server code with password proof")
        await runner.expectThrowsErrorAsync(AccountTwoFactorError.serverRejected, "recovery endpoint errors do not expose the response body") {
            _ = try await management.revealRecoveryCode(for: lease, password: Fixtures.password)
        }
        runner.expectTrue(try await management.revealRecoveryCode(for: lease, password: Fixtures.password) == nil,
                          "recovery preserves an explicit no-code response")

        let setup = try await management.beginAuthenticatorSetup(for: lease, password: Fixtures.password)
        runner.expectTrue(setup.secret == secret, "TOTP setup presents the server's fresh base32 secret")
        let beforeEnable = AccountTwoFactorFixture.calls.count
        await runner.expectThrowsErrorAsync(RepositoryError.authenticationFailed, "finishing TOTP setup re-verifies the password") {
            try await management.enableAuthenticator(setup, code: "012345", password: "wrong password", for: lease)
        }
        runner.expect(AccountTwoFactorFixture.calls.count, beforeEnable, "bad password cannot activate an issued setup grant")
        try await management.enableAuthenticator(setup, code: "012345", password: Fixtures.password, for: lease)
        try await management.removeAuthenticator(for: lease, password: Fixtures.password)

        await runner.expectThrowsErrorAsync(AccountTwoFactorError.configurationChanged, "email setup does not replace an enabled address") {
            _ = try await management.beginEmailSetup(address: address, for: lease, password: Fixtures.password)
        }
        let email = try await management.beginEmailSetup(address: address, for: lease, password: Fixtures.password)
        runner.expect(email.address, address, "email setup is tied to the address confirmed by the user")
        await runner.expectThrowsErrorAsync(AccountTwoFactorError.invalidCode, "email enrollment does not enable a code length unsupported at native sign-in") {
            try await management.enableEmail(email, code: "01234567", password: Fixtures.password, for: lease)
        }
        try await management.enableEmail(email, code: "012345", password: Fixtures.password, for: lease)
        await runner.expectThrowsErrorAsync(AccountTwoFactorError.changeUnconfirmed, "an empty success response alone cannot confirm email removal") {
            try await management.removeEmail(for: lease, password: Fixtures.password)
        }

        let keys = try await management.securityKeys(for: lease, password: Fixtures.password)
        runner.expect(keys.map(\.id), [17], "configured security keys use numeric management IDs")
        guard let key = keys.first else { runner.expectTrue(false, "2FA key fixture returned no key"); return }
        await runner.expectThrowsErrorAsync(AccountTwoFactorError.configurationChanged, "stale key identity never dispatches a delete") {
            _ = try await management.removeSecurityKey(key, for: lease, password: Fixtures.password)
        }
        runner.expect(try await management.removeSecurityKey(key, for: lease, password: Fixtures.password).count, 0,
                      "key removal verifies server's remaining key list")

        let beforeUnavailable = AccountTwoFactorFixture.calls.count
        await runner.expectThrowsErrorAsync(WebAuthnSecondFactorError.unsupported, "an unassociated domain cannot request key enrollment") {
            _ = try await management.registerSecurityKey(name: "New key", for: lease, password: Fixtures.password,
                                                         isAvailable: { _ in false }, authorize: { _, _ in throw CancellationError() })
        }
        runner.expect(AccountTwoFactorFixture.calls.count, beforeUnavailable, "registration checks the platform domain policy before reaching a server")
        await runner.expectThrowsErrorAsync(AccountTwoFactorError.unsupportedServer, "a challenge without ES256 never invokes native authorization") {
            _ = try await management.registerSecurityKey(name: "New key", for: lease, password: Fixtures.password,
                                                         isAvailable: { _ in true }, authorize: { _, _ in throw CancellationError() })
        }
        await runner.expectThrowsErrorAsync(WebAuthnSecondFactorError.invalidAssertion, "registration rejects a credential for a different HTTPS origin") {
            _ = try await management.registerSecurityKey(name: "New key", for: lease, password: Fixtures.password, isAvailable: { _ in true }) {
                try factorAttestation(for: $0, origin: "https://elsewhere.example.test", environment: $1)
            }
        }
        let addedKeys = try await management.registerSecurityKey(name: "New key", for: lease, password: Fixtures.password, isAvailable: { _ in true }) {
            try factorAttestation(for: $0, origin: "https://factors.example.test", environment: $1)
        }
        runner.expect(addedKeys.map(\.name), ["New key"], "registration confirms the exact new management key in the server response")
        await runner.expectThrowsErrorAsync(WebAuthnSecondFactorError.invalidAssertion, "registration rejects a credential already excluded by the server") {
            _ = try await management.registerSecurityKey(name: "Duplicate key", for: lease, password: Fixtures.password, isAvailable: { _ in true }) {
                try factorAttestation(for: $0, origin: "https://factors.example.test", environment: $1)
            }
        }

        let staleSetup = try await management.beginAuthenticatorSetup(for: lease, password: Fixtures.password)
        let pendingRecovery = Task { try await management.revealRecoveryCode(for: lease, password: Fixtures.password) }
        let deadline = ContinuousClock.now + .seconds(5)
        while AccountTwoFactorFixture.remaining > 0 && .now < deadline {
            try await Task.sleep(for: .milliseconds(10))
        }
        runner.expect(AccountTwoFactorFixture.remaining, 0, "the recovery request is suspended in the transport before lock")
        await auth.lock()
        releaseRecovery.signal()
        await runner.expectThrowsErrorAsync(RepositoryError.locked, "a recovery code arriving after lock is discarded") {
            _ = try await pendingRecovery.value
        }
        await runner.expectThrowsErrorAsync(RepositoryError.locked, "locking invalidates the recovery lease") {
            _ = try await management.revealRecoveryCode(for: lease, password: Fixtures.password)
        }
        try await auth.unlockWithMasterPassword(Fixtures.password)
        guard let newLease = await management.unlockedSessionLease() else {
            runner.expectTrue(false, "2FA settings fixture re-unlocked"); return
        }
        await runner.expectThrowsErrorAsync(AccountTwoFactorError.setupExpired, "a re-unlock of the same account cannot reuse a setup grant") {
            try await management.enableAuthenticator(staleSetup, code: "012345", password: Fixtures.password, for: newLease)
        }

        let calls = AccountTwoFactorFixture.calls.filter { $0.path.hasPrefix(root) }
        runner.expect(AccountTwoFactorFixture.remaining, 0, "2FA fixture consumed its request sequence without replay")
        runner.expectTrue(calls.allSatisfy { $0.correctRoute && $0.isPrivate }, "2FA uses the bound HTTPS server, bearer, and no-store flag")
        let protectedReads = calls.filter { $0.path.contains("/get-") && !$0.path.hasSuffix("/get-webauthn-challenge") }
        runner.expectTrue(protectedReads.allSatisfy { $0.fields == ["masterPasswordHash"] && $0.hasDerivedProof },
                          "protected reads send only the derived password proof")
        let activateTOTP = calls.first { $0.method == "PUT" && $0.path.hasSuffix("/authenticator") }
        runner.expectTrue(activateTOTP?.token == "012345" && activateTOTP?.hasKey == true && activateTOTP?.verification == "auth-off",
                          "TOTP activation carries the setup token, its key, and a string code with leading zero")
        let removeTOTP = calls.first { $0.method == "DELETE" && $0.path.hasSuffix("/authenticator") }
        runner.expectTrue(removeTOTP?.hasKey == true && removeTOTP?.verification == "auth-on",
                          "TOTP deletion uses a fresh proof bound to the currently enabled key")
        let emailSend = calls.first { $0.path.hasSuffix("/send-email") }
        let emailEnable = calls.first { $0.method == "PUT" && $0.path.hasSuffix("/email") }
        let emailRemove = calls.first { $0.method == "DELETE" && $0.path.hasSuffix("/email") }
        runner.expectTrue(emailSend?.email == address && emailSend?.verification == "email-off" && emailEnable?.email == address &&
                          emailEnable?.token == "012345" && emailRemove?.verification == "email-on",
                          "email setup and removal use the known routes and send a six-digit string code")
        let removeKey = calls.first { $0.method == "DELETE" && $0.path.hasSuffix("/webauthn") }
        runner.expectTrue(removeKey?.id == 17 && removeKey?.verification == "key-proof", "security key removal uses the numeric key ID and bound token")
        let challenges = calls.filter { $0.path.hasSuffix("/get-webauthn-challenge") }
        runner.expectTrue(challenges.compactMap(\.verification) == ["register-proof", "register-proof", "register-proof", "second-proof"] &&
                          challenges.allSatisfy { $0.fields == ["userVerificationToken"] },
                          "registration challenges only send their state-bound verification token")
        let keyEnrollments = calls.filter { $0.method == "PUT" && $0.path.hasSuffix("/webauthn") }
        runner.expectTrue(keyEnrollments.count == 1 && keyEnrollments.first?.id == 1 &&
                          keyEnrollments.first?.verification == "register-proof" && keyEnrollments.first?.hasAttestation == true,
                          "registration does not replay and submits the exact device response and verification token")
    } catch {
        runner.expectTrue(false, "unexpected failure in account 2FA management fixture")
    }
}

private func factorBase64URL(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

private func factorAttestation(for challenge: TwoFactorSecurityKeyRegistrationChallenge, origin: String,
                               environment: ServerEnvironment) throws -> TwoFactorSecurityKeyAttestation {
    let host = try TwoFactorSecurityKeyRegistrationChallenge.relyingPartyIdentifier(for: environment)
    let id = Data([1, 3, 5])
    let publicKey = P256.Signing.PrivateKey().publicKey.x963Representation
    // Minimal none attestation with an EC2/ES256/P-256 public key and user presence.
    var authData = Data(SHA256.hash(data: Data(host.utf8)))
    authData += Data([0x41] + Array(repeating: 0, count: 21) + [UInt8(id.count)]) + id
    authData += Data([0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 32]) + publicKey[1...32]
    authData += Data([0x22, 0x58, 32]) + publicKey[33...64]
    var object = Data([0xa3, 0x63]) + Data("fmt".utf8) + Data([0x64]) + Data("none".utf8)
    object += Data([0x67]) + Data("attStmt".utf8) + Data([0xa0, 0x68]) + Data("authData".utf8)
    object += Data([0x58, UInt8(authData.count)]) + authData
    let client = try JSONSerialization.data(withJSONObject: ["type": "webauthn.create", "origin": origin,
                                                            "challenge": factorBase64URL(challenge.challenge)])
    return .init(credentialID: id, clientDataJSON: client, attestationObject: object)
}

private final class AccountTwoFactorFixture: URLProtocol, @unchecked Sendable {
    struct Reply: Sendable {
        let method: String
        let path: String
        let body: String
        let status: Int
        let waitFor: DispatchSemaphore?

        init(_ method: String, _ path: String, _ body: String, status: Int = 200, waitFor: DispatchSemaphore? = nil) {
            self.method = method
            self.path = path
            self.body = body
            self.status = status
            self.waitFor = waitFor
        }
    }

    struct Call: Sendable {
        let method: String
        let path: String
        let correctRoute: Bool
        let isPrivate: Bool
        let fields: Set<String>
        let hasDerivedProof: Bool
        let hasKey: Bool
        let verification: String?
        let token: String?
        let email: String?
        let id: Int?
        let hasAttestation: Bool
    }

    private struct State {
        var replies: [Reply] = []
        var calls: [Call] = []
    }

    private static let state = OSAllocatedUnfairLock(initialState: State())
    static var calls: [Call] { state.withLock { $0.calls } }
    static var remaining: Int { state.withLock { $0.replies.count } }
    static func reset() { state.withLock { $0 = State() } }
    static func script(_ replies: [Reply]) { state.withLock { $0 = State(replies: replies) } }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url, let method = request.httpMethod else { return }
        let data = request.httpBody ?? request.httpBodyStream.map(Self.read)
        let json = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
        let path = url.path
        let headersArePrivate = request.value(forHTTPHeaderField: "Authorization") == "Bearer factor-bearer" &&
            request.value(forHTTPHeaderField: "Cache-Control")?.contains("no-store") == true
        let proof = (json["masterPasswordHash"] as? String).flatMap { Data(base64Encoded: $0) }
        let credential = json["deviceResponse"] as? [String: Any]
        let responseFields = credential?["response"] as? [String: String]
        let hasAttestation = credential?["type"] as? String == "public-key" && credential?["id"] as? String == "AQMF" &&
            credential?["rawId"] as? String == "AQMF" && responseFields?.keys.sorted() == ["attestationObject", "clientDataJson"]
        let call = Call(method: method, path: path,
                        correctRoute: url.scheme == "https" && url.host == "factors.example.test" && url.query == nil,
                        isPrivate: headersArePrivate, fields: Set(json.keys), hasDerivedProof: proof?.count == 32,
                        hasKey: (json["key"] as? String)?.utf8.count == 32, verification: json["userVerificationToken"] as? String,
                        token: json["token"] as? String, email: json["email"] as? String, id: json["id"] as? Int,
                        hasAttestation: hasAttestation)
        let reply = Self.state.withLock { state -> Reply in
            state.calls.append(call)
            guard let head = state.replies.first, head.method == method, head.path == path else {
                return Reply(method, path, "{}", status: 500)
            }
            return state.replies.removeFirst()
        }
        _ = reply.waitFor?.wait(timeout: .now() + .seconds(10))
        let response = HTTPURLResponse(url: url, statusCode: reply.status, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(reply.body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func read(_ stream: InputStream) -> Data {
        stream.open()
        defer { stream.close() }
        var bytes = [UInt8](repeating: 0, count: 512)
        var body = Data()
        while stream.hasBytesAvailable {
            let count = stream.read(&bytes, maxLength: bytes.count)
            guard count > 0 else { break }
            body.append(contentsOf: bytes.prefix(count))
        }
        return body
    }
}
