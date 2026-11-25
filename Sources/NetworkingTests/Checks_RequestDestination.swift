import Foundation
import Networking

func checkSecureTransportFirstHop(_ runner: inout TestRunner) async {
    let cleartext = ServerEnvironment(string: "http://vault.example.test/proxy")!
    let secure = ServerEnvironment(base: URL(string: "https://vault.example.test:8443/proxy/a%2Fb")!,
                                   identityURL: URL(string: "https://identity.example.test:8443/tenant/identity")!,
                                   apiURL: URL(string: "https://api.example.test:8443/tenant/api")!)
    let email = "fixture@example.test"
    let denial = NetworkingError.transport("The request destination is not allowed")
    let box = StubBox(response: .json(Fixtures.prelogin))
    let session = makeStubbedSession(box: box)
    defer { session.invalidateAndCancel() }
    let client = APIClient(environment: cleartext, session: session, device: Fixtures.device,
                           clientVersion: Fixtures.clientVersion)
    let permissive = APIClient(environment: cleartext, session: session, device: Fixtures.device,
                               clientVersion: Fixtures.clientVersion, requestAllowed: { _ in true })
    runner.expectTrue(!client.allowsServer(cleartext), "transport: the production policy rejects cleartext")
    runner.expectTrue(client.allowsServer(secure), "transport: split HTTPS bases are valid")
    for url in ["http://vault.example.test:8080", "http://localhost:8080", "http://127.0.0.1",
                "http://127.0.0.2:8080", "http://127.0.0.1:0", "https://@vault.example.test",
                "https://vault.example.test:65536", "https://vault.example.test/root?query", "ftp://vault.example.test"] {
        let server = ServerEnvironment(base: URL(string: url)!)
        runner.expectTrue(!permissive.allowsServer(server), "transport: even an injected predicate cannot enable \(url)")
    }

    await client.bindAccount("owner", contextID: UUID())
    await client.setAccessToken("synthetic-bearer")
    let blocked: [(String, () async throws -> Void)] = [
        ("prelogin", { _ = try await client.prelogin(email: email) }),
        ("password grant", { _ = try await client.token(email: email, passwordHash: "synthetic-hash") }),
        ("refresh", { _ = try await client.refresh(refreshToken: "synthetic-refresh") }),
        ("scoped refresh", { _ = try await client.refresh(refreshToken: "synthetic-refresh", server: cleartext, accountID: "owner") }),
        ("email code", { try await client.sendEmailLoginCode(email: email, masterPasswordHash: "synthetic-hash", server: cleartext) }),
        ("password hint", { try await client.requestPasswordHint(email: email, server: cleartext) }),
        ("authenticated sync", { _ = try await client.sync(accountID: "owner", excludeDomains: true) }),
        ("Send", { _ = try await client.sends(accountID: "owner") }),
        ("cipher create before dispatch", { _ = try await client.createCipher(accountID: "owner", .init(type: 1, name: Fixtures.enc())) }),
        ("config", { _ = try await client.config() }),
    ]
    for (label, request) in blocked {
        await runner.expectThrowsErrorAsync(denial, "transport: \(label) cannot use an HTTP deployment", request)
    }
    do {
        runner.expect(try await client.alive(), false, "transport: alive does not probe HTTP")
    } catch {
        runner.expectTrue(false, "transport: alive unexpectedly threw \(error)")
    }

    var mixed = secure
    mixed.identityURL = cleartext.identityBase
    await runner.expectThrowsErrorAsync(denial, "transport: HTTPS API cannot mask a cleartext identity override") {
        try await client.sendEmailLoginCode(email: email, masterPasswordHash: "synthetic-hash", server: mixed)
    }
    mixed = secure
    mixed.apiURL = cleartext.apiBase
    await runner.expectThrowsErrorAsync(denial, "transport: HTTPS identity cannot mask a cleartext API override") {
        _ = try await client.prelogin(email: email, server: mixed)
    }
    mixed = secure
    mixed.base = cleartext.base
    await runner.expectThrowsErrorAsync(denial, "transport: HTTPS overrides cannot mask a cleartext base") {
        _ = try await client.prelogin(email: email, server: mixed)
    }
    runner.expect(box.capturedCount, 0, "transport: every denied first hop stays out of URLSession")

    do {
        _ = try await client.prelogin(email: email, server: secure)
        runner.expect(box.captured?.url.absoluteString, "https://identity.example.test:8443/tenant/identity/accounts/prelogin",
                      "transport: explicit TLS identity retains its reverse-proxy path and port")
        await client.setEnvironment(secure)
        box.response = .json(Fixtures.config)
        _ = try await client.config()
        runner.expect(box.captured?.url.absoluteString, "https://api.example.test:8443/tenant/api/config",
                      "transport: TLS API override retains its reverse-proxy path and port")
        runner.expect(try await client.alive(), true, "transport: TLS health probe returns success")
        runner.expect(box.captured?.url.absoluteString, "https://vault.example.test:8443/proxy/a%2Fb/alive",
                      "transport: percent-encoded deployment subpath is preserved")
    } catch {
        runner.expectTrue(false, "transport: split HTTPS requests failed: \(error)")
    }
}

func checkReturnedResponseDestinations(_ runner: inout TestRunner) async {
    let box = StubBox(response: .init(statusCode: 307, headers: ["Location": "http://other.example.test/next"]))
    let client = Fixtures.client(box: box)
    let redirect = NetworkingError.http(status: 307, body: "Redirects are not allowed")
    await runner.expectThrowsErrorAsync(redirect, "transport: a returned redirect cannot serve as a password-grant response") {
        _ = try await client.token(email: "fixture@example.test", passwordHash: "synthetic-hash")
    }
    await runner.expectThrowsErrorAsync(redirect, "transport: a returned redirect cannot acknowledge a mail-code request") {
        try await client.sendEmailLoginCode(email: "fixture@example.test", masterPasswordHash: "synthetic-hash",
                                            server: Fixtures.environment())
    }
    await runner.expectThrowsErrorAsync(redirect, "transport: a returned redirect cannot grant a refreshed token") {
        _ = try await client.refresh(refreshToken: "synthetic-refresh")
    }
    runner.expect(box.capturedCount, 3, "transport: returned redirects do not cause a replay")

    box.response = .init(body: Data(Fixtures.prelogin.utf8), responseURL: URL(string: "https://other.example.test/next"))
    await runner.expectThrowsErrorAsync(NetworkingError.decoding("Unexpected response URL"),
                                       "transport: an unexpected final response URL cannot provide login parameters") {
        _ = try await client.prelogin(email: "fixture@example.test")
    }
    runner.expect(box.capturedCount, 4, "transport: no retry after an unexpected final response URL")

    box.response = .init(delivery: .failure(.serverCertificateUntrusted))
    await runner.expectThrowsAsync("transport: an untrusted TLS connection fails without a fallback") {
        _ = try await client.refresh(refreshToken: "synthetic-refresh")
    }
    runner.expect(box.capturedCount, 5, "transport: a TLS trust failure is not retried")
    runner.expect(box.captured?.url.scheme, "https", "transport: no fallback to HTTP")
}

func checkRequestDestinationPolicy(_ runner: inout TestRunner) async {
    let allowed = ServerEnvironment(string: "https://vault.example.test:8443")!
    let alternate = ServerEnvironment(string: "https://vault.example.test:9443")!
    let wrongPort = ServerEnvironment(string: "https://vault.example.test:8444")!
    let wrongHost = ServerEnvironment(string: "https://other.example.test:8443")!
    let preloginPath = "/identity/accounts/prelogin"
    let sendsPath = "/api/sends"
    let uploadPath = "/api/sends/item-1/file/file-1"
    let box = StubBox(response: .init(statusCode: 500), responsesByPath: [
        preloginPath: .json(Fixtures.prelogin), sendsPath: .json(#"{"data":[]}"#), uploadPath: .init(statusCode: 204)
    ])
    let session = makeStubbedSession(box: box)
    defer { session.invalidateAndCancel() }
    let client = APIClient(environment: wrongPort, session: session, device: Fixtures.device,
                           clientVersion: Fixtures.clientVersion, requestAllowed: { url in
        url.scheme == "https" && url.host == "vault.example.test" && (url.port == 8443 || url.port == 9443)
    })
    let denial = NetworkingError.transport("The request destination is not allowed")
    await runner.expectThrowsErrorAsync(denial, "request scope: an explicit prelogin to another host is denied") {
        _ = try await client.prelogin(email: "fixture@example.test", server: wrongHost)
    }
    await runner.expectThrowsErrorAsync(denial, "request scope: prelogin to an unlisted port is denied") {
        _ = try await client.prelogin(email: "fixture@example.test")
    }
    runner.expect(box.capturedCount, 0, "request scope: denied identity requests never reach URLSession")

    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: temporary) }
    do {
        try Data("synthetic multipart fixture".utf8).write(to: temporary)
        await client.setAccountID("owner")
        try await client.setAccessToken("fixture-bearer", for: "owner")
        await runner.expectThrowsErrorAsync(denial, "request scope: Send listing to an unlisted port is denied") {
            _ = try await client.sends(accountID: "owner")
        }
        await runner.expectThrowsErrorAsync(denial, "request scope: Send upload to an unlisted port is denied") {
            try await client.uploadSendFile(accountID: "owner", id: "item-1", fileID: "file-1", multipart: temporary, boundary: "fixture")
        }
        runner.expect(box.capturedCount, 0, "request scope: denied Send data and uploads never reach URLSession")

        await client.setEnvironment(allowed)
        _ = try await client.prelogin(email: "fixture@example.test")
        runner.expect(box.captured?.path, preloginPath, "request scope: permitted identity request uses the expected route")
        await client.setAccountID("owner")
        try await client.setAccessToken("fixture-bearer", for: "owner")
        runner.expect(try await client.sends(accountID: "owner").count, 0, "request scope: permitted Send listing is read")
        runner.expect(box.captured?.path, sendsPath, "request scope: permitted Send listing uses the expected route")
        try await client.uploadSendFile(accountID: "owner", id: "item-1", fileID: "file-1", multipart: temporary, boundary: "fixture")
        runner.expect(box.captured?.path, uploadPath, "request scope: permitted Send upload uses the expected route")
        runner.expect(box.captured?.url.port, 8443, "request scope: Send transport preserves the explicitly permitted port")
        runner.expect(box.captured?.header("Authorization"), "Bearer fixture-bearer", "request scope: permitted Send retains authentication")

        _ = try await client.prelogin(email: "fixture@example.test", server: alternate)
        runner.expect(box.captured?.url.port, 9443, "request scope: an explicitly permitted alternate port also works")
        runner.expect(box.capturedCount, 4, "request scope: only the four permitted requests reach URLSession")
    } catch {
        runner.expectTrue(false, "request scope: permitted fixture request failed: \(error)")
    }
}
