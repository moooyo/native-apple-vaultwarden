import AppShared
import CryptoCore
import Foundation
import Networking
import os
import VaultModels
import VaultRepository
import VaultStore

private struct CapturedSendRequest {
    let route: String
    let body: Data
    let contentType: String
}

private final class FunctionalSendTransport: URLProtocol, @unchecked Sendable {
    struct State {
        var nextID = 1
        var records: [String: [String: Any]] = [:]
        var requests: [CapturedSendRequest] = []
        var rejectUpload = false
    }

    static let state = OSAllocatedUnfairLock(uncheckedState: State())

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url, url.host == Fixtures.server.base.host,
              request.value(forHTTPHeaderField: "Authorization") == "Bearer send-functional-fixture" else {
            client?.urlProtocol(self, didFailWithError: URLError(.userAuthenticationRequired)); return
        }
        let body = request.httpBody ?? Self.bytes(request.httpBodyStream)
        let (status, data) = Self.state.withLockUnchecked { state in
            Self.respond(request: request, url: url, body: body, state: &state)
        }
        let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func bytes(_ stream: InputStream?) -> Data {
        guard let stream else { return Data() }
        stream.open()
        defer { stream.close() }
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let length = stream.read(&buffer, maxLength: buffer.count)
            guard length > 0 else { return result }
            result.append(buffer, count: length)
        }
    }

    private static func respond(request: URLRequest, url: URL, body: Data, state: inout State) -> (Int, Data) {
        let path = url.path.split(separator: "/").map(String.init)
        let method = request.httpMethod ?? "GET"
        state.requests.append(.init(route: "\(method) \(url.path)", body: body, contentType: request.value(forHTTPHeaderField: "Content-Type") ?? ""))
        guard path.starts(with: ["api", "sends"]) else { return (404, Data()) }
        func json(_ value: Any) -> (Int, Data) { (200, (try? JSONSerialization.data(withJSONObject: value)) ?? Data()) }
        if method == "GET", path.count == 2 { return json(["data": Array(state.records.values)]) }
        let input = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] ?? [:]
        let fileReservation = path == ["api", "sends", "file", "v2"]
        if method == "POST", path.count == 2 || fileReservation {
            guard input["key"] is String, input["name"] is String else { return (400, Data()) }
            let id = "owner-\(state.nextID)"
            state.nextID += 1
            var record = input
            record["id"] = id
            record["accessId"] = Data(repeating: UInt8(state.nextID), count: 16).base64EncodedString().replacingOccurrences(of: "=", with: "")
            record["revisionDate"] = "2026-01-01T00:00:00Z"
            record["accessCount"] = 0
            if fileReservation {
                guard let file = input["file"] as? [String: Any], let name = file["fileName"] as? String,
                      input["disabled"] as? Bool == true, input["fileLength"] is Int else { return (400, Data()) }
                record["file"] = ["id": "upload-1", "fileName": name]
            }
            state.records[id] = record
            return fileReservation ? json(["fileUploadType": 0, "sendResponse": record]) : json(record)
        }
        guard path.count >= 3, var record = state.records[path[2]] else { return (404, Data()) }
        let id = path[2]
        switch (method, Array(path.dropFirst(3))) {
        case ("GET", []): return json(record)
        case ("PUT", []):
            record.merge(input) { _, new in new }; state.records[id] = record
            return json(record)
        case ("PUT", ["remove-password"]):
            record.removeValue(forKey: "password"); state.records[id] = record
            return json(record)
        case ("POST", ["file", "upload-1"]):
            return (state.rejectUpload ? 503 : 204, Data())
        case ("DELETE", []): state.records[id] = nil; return (204, Data())
        default: return (400, Data())
        }
    }

    static func requests() -> [CapturedSendRequest] { state.withLockUnchecked { $0.requests } }
}

private func checkUploadedFile(_ runner: inout TestRunner, encryptedLength: Int?, captured: CapturedSendRequest?,
                               send: VaultSend, expectedBytes: Data) throws {
    guard let request = captured, let boundary = request.contentType.components(separatedBy: "boundary=").last,
          boundary != request.contentType, !boundary.isEmpty,
          let headerEnd = request.body.range(of: Data("\r\n\r\n".utf8)),
          let footer = request.body.range(of: Data("\r\n--\(boundary)--\r\n".utf8), options: .backwards),
          headerEnd.upperBound < footer.lowerBound else {
        runner.expectTrue(false, "file Send: upload carries a complete multipart body"); return
    }
    let binary = request.body.subdata(in: headerEnd.upperBound..<footer.lowerBound)
    runner.expect(binary.count, encryptedLength, "file Send: reservation size matches only the encrypted file, not multipart framing")
    runner.expect(request.body.range(of: expectedBytes), nil, "file Send: source bytes never reach the HTTP body as plaintext")
    guard binary.count > 49, binary.first == 2, let fragment = send.shareURL.fragment,
          let encoded = fragment.split(separator: "/").last,
          let seed = Data(base64Encoded: String(encoded).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + "==") else {
        runner.expectTrue(false, "file Send: link contains a recipient seed and upload carries a binary encrypted file"); return
    }
    let encrypted = EncString(type: .aesCbc256_HmacSha256_B64, iv: binary.subdata(in: 1..<17), ciphertext: binary.suffix(from: 49), mac: binary.subdata(in: 17..<49))
    let key = try SendCryptography.contentKey(secret: seed)
    runner.expectTrue(try SymmetricCrypto.decrypt(encrypted, using: key) == expectedBytes, "file Send: recipient's link key opens the original multipart payload")
}

func checkFunctionalSendProtocol(_ runner: inout TestRunner) async {
    do {
        let harness = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())])
        defer { Fixtures.cleanup(harness.dir) }
        _ = try await harness.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        guard let accountID = await harness.auth.currentSessionLease()?.accountID else { runner.expectTrue(false, "functional Send fixture: missing account"); return }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [FunctionalSendTransport.self]
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel(); FunctionalSendTransport.state.withLockUnchecked { $0 = .init() } }
        let device = DeviceMetadata(type: DeviceMetadata.DeviceType.iOS, identifier: "send-functional-test", name: "Fixture")
        let client = APIClient(environment: Fixtures.server, session: session, device: device, clientVersion: "1")
        await client.setAccountID(accountID)
        try await client.setAccessToken("send-functional-fixture", for: accountID)
        let encryptor = UserKeyEncryptor()
        await encryptor.setUserKey(Fixtures.userKey())
        let sends = SendRepository(api: client, store: harness.store, keyVault: harness.keyVault, encryptor: encryptor, auth: harness.auth)
        runner.expect(try await sends.listSends().count, 0, "functional Send: start from an authoritative empty collection")
        let deadline = Date.now.addingTimeInterval(86_400)
        var draft = VaultSendDraft(kind: .text, name: "Private fixture caption", text: "Text for this fixture only", hideText: true,
                                   deletionDate: deadline, maxAccessCount: 3, password: "disposable access phrase", hideEmail: true, notes: "fixture private notes")
        let text = try await sends.createSend(draft)
        runner.expect(text.text, draft.text, "text Send: created content is decrypted from the server reply")
        runner.expect(text.hasPassword, true, "text Send: access password is present")
        runner.expect(text.maxAccessCount, 3, "text Send: access limit round-trips")
        runner.expectTrue(text.shareURL.fragment?.hasPrefix("/send/") == true && text.shareURL.query == nil, "text Send: share key is only in the fragment")
        let creation = FunctionalSendTransport.requests().last?.body ?? Data()
        for value in [draft.name, draft.text, draft.notes!, draft.password!] {
            runner.expect(creation.range(of: Data(value.utf8)), nil, "text Send: HTTP creation does not expose the corresponding plaintext")
        }
        draft.name = "Updated metadata fixture"
        draft.password = nil
        draft.removePassword = true
        draft.disabled = true
        draft.maxAccessCount = 1
        let edited = try await sends.updateSend(id: text.id, draft: draft)
        runner.expect(edited.name, draft.name, "text Send: metadata edit reads back under the same key")
        runner.expectTrue(edited.disabled && !edited.hasPassword && edited.maxAccessCount == 1, "text Send: disabling, removing password and updating limit preserve their meanings")
        runner.expect(edited.shareURL, text.shareURL, "text Send: metadata changes preserve the share link")
        runner.expect(FunctionalSendTransport.requests().suffix(3).map(\.route), ["GET /api/sends/\(text.id)", "PUT /api/sends/\(text.id)", "PUT /api/sends/\(text.id)/remove-password"], "text Send: verified update and dedicated password removal occur in order")

        let fileURL = harness.dir.appendingPathComponent("private-fixture-file.bin")
        let source = Data((0..<93_415).map { UInt8(truncatingIfNeeded: $0) })
        try source.write(to: fileURL)
        let fileDraft = VaultSendDraft(kind: .file, name: "Private file fixture", fileURL: fileURL, deletionDate: deadline, maxAccessCount: 2)
        let file = try await sends.createSend(fileDraft)
        let fileCalls = Array(FunctionalSendTransport.requests().suffix(3))
        runner.expect(fileCalls.map(\.route), ["POST /api/sends/file/v2", "POST /api/sends/\(file.id)/file/upload-1", "PUT /api/sends/\(file.id)"], "file Send: reserve disabled, upload, then publish")
        runner.expect(file.fileName, fileURL.lastPathComponent, "file Send: returned encrypted filename decrypts to the selected source name")
        runner.expectTrue(!file.disabled, "file Send: only the completed upload is published")
        let reservation = try JSONSerialization.jsonObject(with: fileCalls[0].body) as? [String: Any]
        runner.expect(reservation?["disabled"] as? Bool, true, "file Send: recipients cannot open the reservation before upload")
        runner.expect(fileCalls[0].body.range(of: Data(fileURL.lastPathComponent.utf8)), nil, "file Send: reservation does not send a plaintext filename")
        try checkUploadedFile(&runner, encryptedLength: reservation?["fileLength"] as? Int, captured: fileCalls[1], send: file, expectedBytes: source)
        runner.expect(try await sends.listSends().map(\.id).sorted(), [text.id, file.id].sorted(), "functional Send: GET list is independently loaded and decrypted")

        FunctionalSendTransport.state.withLockUnchecked { $0.rejectUpload = true }
        await runner.expectThrowsErrorAsync(NetworkingError.http(status: 503, body: "Send request rejected"), "file Send: failed upload cannot return a working-looking share link") { _ = try await sends.createSend(fileDraft) }
        let failureCalls = FunctionalSendTransport.requests().suffix(3).map(\.route)
        runner.expect(failureCalls, ["POST /api/sends/file/v2", "POST /api/sends/owner-3/file/upload-1", "DELETE /api/sends/owner-3"], "file Send: failed upload deletes its reservation without publishing")
        runner.expect(try await harness.store.completeCachedSends(accountID: accountID)?.map(\.id).sorted(), [file.id, text.id].sorted(), "file Send: the failed reservation never enters the offline collection")
        try await sends.deleteSend(id: text.id)
        try await sends.deleteSend(id: file.id)
        runner.expect(try await sends.listSends().count, 0, "functional Send: confirmed deletes remove both returned owner IDs")
        runner.expect(try await harness.store.completeCachedSends(accountID: accountID)?.count, 0, "functional Send: online and encrypted offline collection converge")
    } catch { runner.expectTrue(false, "functional Send protocol fixture: \(error)") }
}
