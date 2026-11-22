import Foundation
import Networking

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
