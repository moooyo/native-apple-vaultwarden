import CryptoCore
import Foundation
@testable import Networking

func checkSendRequests(_ runner: inout TestRunner) async {
    let encrypted = Fixtures.validEnc(seed: 1)
    let record = """
    {"Id":"item-1","AccessId":"ct2APRQtJk-BLLDwAYqhRA","Type":0,"Key":"\(encrypted)",
    "Name":"\(encrypted)","Text":{"Text":"\(encrypted)","Hidden":true},"AccessCount":1,
    "MaxAccessCount":3,"Disabled":false,"RevisionDate":"2025-01-01T01:00:00.735Z","DeletionDate":"2025-01-02T01:00:00Z"}
    """
    let box = StubBox(response: .json("{\"Data\":[\(record)]}"))
    let client = Fixtures.client(box: box)
    await client.setAccountID("account")
    await runner.expectThrowsErrorAsync(NetworkingError.accountContextChanged, "reject Send listing on the wrong account") {
        _ = try await client.sends(accountID: "other")
    }
    runner.expectTrue(box.captured == nil, "rejected Send request never left the process")
    do {
        try await client.setAccessToken("send-token", for: "account")
        let records = try await client.sends(accountID: "account")
        runner.expect(records.first?.maxAccessCount, 3, "Send response decodes mixed casing")
        runner.expect(records.first?.text?.hidden, true, "Send preserves hidden text")
        runner.expect(box.captured?.path, "/api/sends", "owner Send listing endpoint")
        runner.expect(box.captured?.header("Authorization"), "Bearer send-token", "owner operations use bearer")
        for tokenKey in ["continuationToken", "ContinuationToken"] {
            box.response = .json("{\"data\":[],\"\(tokenKey)\":\"another-page\"}")
            await runner.expectThrowsErrorAsync(NetworkingError.decoding("Incomplete Send listing"), "a Send page is not a complete listing") {
                _ = try await client.sends(accountID: "account")
            }
        }
        let value = try EncString(parsing: encrypted)
        var request = SendRequest(type: 0, key: value, name: value, deletionDate: Date.now,
                                  hideEmail: true, disabled: false)
        request.text = .init(text: value, hidden: true)
        request.maxAccessCount = 7
        box.response = .json(record)
        _ = try await client.createTextSend(accountID: "account", request: request)
        let payload = try JSONSerialization.jsonObject(with: box.captured?.body ?? Data()) as? [String: Any]
        runner.expect(payload?["maxAccessCount"] as? Int, 7, "writes use server camel-case keys")
        runner.expect(payload?["text"].flatMap { $0 as? [String: Any] }?["text"] as? String, encrypted,
                      "wire text contains authenticated ciphertext")
        runner.expect(box.captured?.method, "POST", "create Send is POST")
        _ = try await client.removeSendPassword(accountID: "account", id: "item-1")
        runner.expect(box.captured?.path, "/api/sends/item-1/remove-password", "removing a password uses dedicated endpoint")
        await runner.expectThrowsAsync("reject an invalid Send path segment") {
            try await client.deleteSend(accountID: "account", id: "../folders")
        }
        runner.expect(box.captured?.method, "PUT", "invalid ID did not issue a delete")
    } catch {
        runner.expectTrue(false, "Send API fixtures: \(error)")
    }
    await checkSendTransportPolicy(&runner)
}

private func checkSendTransportPolicy(_ runner: inout TestRunner) async {
    let url = URL(string: "https://vault.example.test/api/sends/item-1/file/file-1")!
    let nextURL = URL(string: "https://unrelated.example.test/login")!
    let session = URLSession(configuration: .ephemeral)
    defer { session.invalidateAndCancel() }
    let task = session.dataTask(with: url)
    let response = HTTPURLResponse(url: url, statusCode: 307, httpVersion: "HTTP/1.1",
                                   headerFields: ["Location": nextURL.absoluteString])!
    let refused: Bool = await withCheckedContinuation { completion in
        DirectHTTPDelegate.shared.urlSession(session, task: task, willPerformHTTPRedirection: response,
                                             newRequest: URLRequest(url: nextURL)) { proposed in
            completion.resume(returning: proposed == nil)
        }
    }
    runner.expectTrue(refused, "Send task delegate refuses redirected upload requests instead of forwarding ciphertext")

    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: temporary) }
    let box = StubBox(response: .init(statusCode: 302, headers: ["Location": nextURL.absoluteString]))
    let client = Fixtures.client(box: box)
    await client.setAccountID("owner")
    do {
        try await client.setAccessToken("send-test-token", for: "owner")
        try Data("synthetic ciphertext".utf8).write(to: temporary)
        await runner.expectThrowsErrorAsync(NetworkingError.http(status: 302, body: "Send request rejected"),
                                           "a redirect is not a deletion acknowledgment") {
            try await client.deleteSend(accountID: "owner", id: "item-1")
        }
        box.response = .init(statusCode: 307, headers: ["Location": nextURL.absoluteString])
        await runner.expectThrowsErrorAsync(NetworkingError.http(status: 307, body: "Send request rejected"),
                                           "a redirected upload cannot be published") {
            try await client.uploadSendFile(accountID: "owner", id: "item-1", fileID: "file-1", multipart: temporary, boundary: "fixture")
        }
        box.response = .init(statusCode: 200, body: Data("<html>Sign in</html>".utf8), headers: ["Content-Type": "text/html"])
        await runner.expectThrowsAsync("a login page is not an upload acknowledgment") {
            try await client.uploadSendFile(accountID: "owner", id: "item-1", fileID: "file-1", multipart: temporary, boundary: "fixture")
        }
        box.response = .init(statusCode: 204)
        try await client.uploadSendFile(accountID: "owner", id: "item-1", fileID: "file-1", multipart: temporary, boundary: "fixture")
        runner.expect(box.captured?.path, url.path, "acknowledgment is from the expected upload route")
    } catch {
        runner.expectTrue(false, "Send transport policy fixtures: \(error)")
    }
}
