import AppShared
import CryptoCore
import Foundation
import Networking

private let deviceLoginID = UUID(uuidString: "01234567-abcd-4321-a987-abcdef012345")!
private let deviceLoginPath = "/vault/api/auth-requests/01234567-abcd-4321-a987-abcdef012345"
private let deviceLoginPublicKey = Data("transport fixture public key".utf8).base64EncodedString()
private let deviceLoginWrappedKey = EncString(type: .rsa2048_OaepSha1_B64, iv: nil,
                                              ciphertext: Data(repeating: 0xa5, count: 256), mac: nil)

private func deviceLoginRecord(id: String = deviceLoginID.uuidString.lowercased(), publicKey: String = deviceLoginPublicKey,
                               approved: Bool? = nil, answered: Bool = false, key: String? = nil,
                               pascalCase: Bool = false) -> [String: Any] {
    let record: [String: Any] = [
        "id": id, "object": "auth-request", "publicKey": publicKey,
        "requestDeviceType": "MacOsDesktop", "requestIpAddress": "192.0.2.1",
        "key": key.map { $0 as Any } ?? NSNull(), "masterPasswordHash": NSNull(),
        "creationDate": "2026-01-02T03:04:05.123456Z",
        "responseDate": answered ? "2026-01-02T03:04:06.123456Z" as Any : NSNull(),
        "requestApproved": approved.map { $0 as Any } ?? NSNull(),
        // This is informational; the next request must use the specified server, not the response origin.
        "origin": "https://untrusted.example.test",
    ]
    guard pascalCase else { return record }
    return Dictionary(uniqueKeysWithValues: record.map { key, value in
        (key.prefix(1).uppercased() + key.dropFirst(), value)
    })
}

private func deviceLoginStub(_ record: [String: Any], status: Int = 200) -> StubResponse {
    StubResponse(statusCode: status, body: try! JSONSerialization.data(withJSONObject: record))
}

func checkDeviceLoginTransport(_ r: inout TestRunner) async {
    let server = ServerEnvironment(string: "https://approval.example.test/vault")!
    let box = StubBox(response: .json("true"))
    let api = Fixtures.client(box: box)
    let accountID = "approval-account"
    let contextID = UUID()
    do {
        let code = try DeviceLoginAccessCode.generate()
        r.expect(code.wireValue.utf8.count, 43, "device login: 32 random bytes encoded without padding")
        r.expectTrue(code.wireValue.range(of: #"^[A-Za-z0-9_-]+$"#, options: .regularExpression) != nil,
                     "device login: access code is URL-safe")
        r.expectTrue(try DeviceLoginAccessCode.generate().wireValue != code.wireValue,
                     "device login: access codes are unique per attempt")
        r.expectTrue(!String(reflecting: code).contains(code.wireValue), "device login: access code reflection is redacted")

        await api.setAccessToken("unrelated-bearer")
        r.expect(try await api.isKnownDeviceForLogin(email: "  Alice+Device@Example.Test ", server: server), true,
                 "device login: known-device probe decodes boolean")
        r.expect(box.captured?.url.host, "approval.example.test", "device login: explicit sign-in server wins")
        r.expect(box.captured?.path, "/vault/api/devices/knowndevice", "device login: known device API route respects proxy base")
        r.expect(box.captured?.method, "GET", "device login: known device uses GET")
        r.expect(box.captured?.header("X-Request-Email"), "YWxpY2UrZGV2aWNlQGV4YW1wbGUudGVzdA",
                 "device login: known device sends unpadded base64url normalized email")
        r.expect(box.captured?.header("X-Device-Identifier"), Fixtures.device.identifier, "device login: probe uses registered device ID")
        r.expect(box.captured?.header("Device-Type"), String(Fixtures.device.type), "device login: probe retains device type")
        r.expect(box.captured?.header("Authorization"), nil, "device login: known-device probe never sends a bearer")
        box.response = .json("false")
        r.expect(try await api.isKnownDeviceForLogin(email: "alice@example.test", server: server), false,
                 "device login: first-use device is not reported as known")

        box.response = deviceLoginStub(deviceLoginRecord(approved: false))
        let request = try await api.createDeviceLoginRequest(email: "Alice+Device@Example.Test", accessCode: code,
                                                            publicKey: deviceLoginPublicKey, server: server)
        r.expect(request.id, deviceLoginID, "device login: creates canonical UUID request")
        r.expect(request.isPending, true, "device login: creation false with no response date means pending")
        r.expect(box.captured?.path, "/vault/api/auth-requests", "device login: create route")
        r.expect(box.captured?.method, "POST", "device login: create uses POST")
        r.expect(box.captured?.header("Authorization"), nil, "device login: create never sends bearer")
        r.expect(box.captured?.header("Content-Type"), "application/json", "device login: create body content type")
        let createBody = try JSONSerialization.jsonObject(with: box.captured?.body ?? Data()) as? [String: String] ?? [:]
        r.expect(Set(createBody.keys), Set(["accessCode", "deviceIdentifier", "email", "publicKey"]),
                 "device login: sends exact Vaultwarden creation keys")
        r.expect(createBody["deviceIdentifier"], Fixtures.device.identifier, "device login: create reuses registered identifier")
        r.expect(createBody["email"], "alice+device@example.test", "device login: create uses the same email as the probe")
        r.expect(createBody["publicKey"], deviceLoginPublicKey, "device login: create sends the matching public key")
        r.expectTrue(createBody["accessCode"] == code.wireValue, "device login: create sends this attempt's access code")

        box.response = deviceLoginStub(deviceLoginRecord(pascalCase: true))
        let waiting = try await api.pollDeviceLoginRequest(id: request.id, accessCode: code, server: server)
        r.expect(waiting.isPending, true, "device login: decoded null approval still means pending")
        r.expect(waiting.requestDeviceType, "MacOsDesktop", "device login: PascalCase device type decodes")
        r.expect(waiting.requestIPAddress, "192.0.2.1", "device login: PascalCase IP decodes")
        r.expect(box.captured?.path, deviceLoginPath + "/response", "device login: anonymous response route")
        r.expect(box.captured?.url.host, "approval.example.test", "device login: polling ignores the response's origin")
        r.expect(box.captured?.header("Authorization"), nil, "device login: anonymous polling never sends bearer")
        r.expect(box.captured?.header("Cache-Control"), "no-store", "device login: credential-bearing poll disallows caching")
        let query = box.captured.flatMap { URLComponents(url: $0.url, resolvingAgainstBaseURL: false)?.queryItems }
        r.expectTrue(query == [URLQueryItem(name: "code", value: code.wireValue)], "device login: poll sends one code query item")

        box.response = deviceLoginStub(deviceLoginRecord(approved: true, answered: true, key: deviceLoginWrappedKey.stringValue))
        let approval = try await api.pollDeviceLoginRequest(id: request.id, accessCode: code, server: server)
        r.expect(approval.requestApproved, true, "device login: approved response distinguishes pending")
        r.expect(approval.key, deviceLoginWrappedKey, "device login: approved response carries type 4 encrypted key")
        r.expectTrue(approval.responseDate != nil, "device login: approval response date decodes")

        box.response = .json(code.wireValue, status: 400)
        await r.expectThrowsErrorAsync(DeviceLoginError.requestUnavailable, "device login: a deleted/invalid request is unavailable") {
            _ = try await api.pollDeviceLoginRequest(id: request.id, accessCode: code, server: server)
        }
        box.response = .json(code.wireValue, status: 429)
        do {
            _ = try await api.pollDeviceLoginRequest(id: request.id, accessCode: code, server: server)
            r.expectTrue(false, "device login: rate limit must not succeed")
        } catch {
            r.expectTrue(!String(reflecting: error).contains(code.wireValue), "device login: HTTP errors redact access code")
        }

        box.response = StubResponse(delivery: .failure(.secureConnectionFailed))
        do {
            _ = try await api.pollDeviceLoginRequest(id: request.id, accessCode: code, server: server)
            r.expectTrue(false, "device login: transport failure must not succeed")
        } catch {
            r.expectTrue(!String(reflecting: error).contains(code.wireValue), "device login: transport errors redact the poll URL")
        }
        box.response = StubResponse(body: try JSONSerialization.data(withJSONObject: deviceLoginRecord()),
                                    responseURL: URL(string: "https://other.example.test/response?code=\(code.wireValue)"))
        await r.expectThrowsErrorAsync(NetworkingError.decoding("Unexpected response URL"),
                                       "device login: a different returned URL is rejected without logging the query") {
            _ = try await api.pollDeviceLoginRequest(id: request.id, accessCode: code, server: server)
        }

        box.response = deviceLoginStub(deviceLoginRecord(id: UUID().uuidString))
        await r.expectThrowsErrorAsync(DeviceLoginError.invalidResponse, "device login: substituted request ID is rejected") {
            _ = try await api.pollDeviceLoginRequest(id: request.id, accessCode: code, server: server)
        }
        box.response = deviceLoginStub(deviceLoginRecord(id: "../pending"))
        await r.expectThrowsAsync("device login: malformed UUID cannot become a path") {
            _ = try await api.pollDeviceLoginRequest(id: request.id, accessCode: code, server: server)
        }
        box.response = deviceLoginStub(deviceLoginRecord(approved: true, answered: true, key: "4.YQ=="))
        await r.expectThrowsAsync("device login: truncated type 4 ciphertext is rejected") {
            _ = try await api.pollDeviceLoginRequest(id: request.id, accessCode: code, server: server)
        }
        box.response = deviceLoginStub(deviceLoginRecord(publicKey: "AQID", approved: false))
        await r.expectThrowsErrorAsync(DeviceLoginError.invalidResponse, "device login: echoed public key does not match this attempt") {
            _ = try await api.createDeviceLoginRequest(email: "alice@example.test", accessCode: code,
                                                       publicKey: deviceLoginPublicKey, server: server)
        }

        let sent = box.capturedCount
        await r.expectThrowsErrorAsync(DeviceLoginError.invalidEmail, "device login: email rejects newline and multiple separators") {
            _ = try await api.isKnownDeviceForLogin(email: "alice\n@example.test@test", server: server)
        }
        await r.expectThrowsErrorAsync(DeviceLoginError.invalidPublicKey, "device login: oversized public key rejected locally") {
            _ = try await api.createDeviceLoginRequest(email: "alice@example.test", accessCode: code,
                                                       publicKey: String(repeating: "A", count: 1_028), server: server)
        }
        for identifier in ["device/other", String(repeating: "A", count: 37)] {
            let invalidDevice = DeviceMetadata(type: Fixtures.device.type, identifier: identifier, name: Fixtures.device.name)
            let invalidAPI = APIClient(environment: server, session: makeStubbedSession(box: box), device: invalidDevice,
                                       clientVersion: Fixtures.clientVersion)
            await r.expectThrowsErrorAsync(DeviceLoginError.invalidDeviceIdentifier,
                                           "device login: malformed or oversized persistent identifier never dispatched") {
                _ = try await invalidAPI.isKnownDeviceForLogin(email: "alice@example.test", server: server)
            }
        }
        let splitServer = ServerEnvironment(base: server.base, apiURL: URL(string: "https://other.example.test/api")!)
        await r.expectThrowsAsync("device login: split-origin API cannot receive the poll code") {
            _ = try await api.pollDeviceLoginRequest(id: request.id, accessCode: code, server: splitServer)
        }
        r.expect(box.capturedCount, sent, "device login: invalid input or destination never dispatched")

        await api.setEnvironment(server)
        await api.bindAccount(accountID, contextID: contextID)
        try await api.installAccessToken("approver-bearer", expiresIn: 600, for: accountID, contextID: contextID)
        box.response = deviceLoginStub(["object": "list", "data": [deviceLoginRecord()], "continuationToken": NSNull()])
        let pending = try await api.pendingDeviceLoginRequests(accountID: accountID, contextID: contextID)
        r.expect(pending.map(\.id), [request.id], "device login: pending requests decode from a bearer-scoped list")
        r.expect(box.captured?.path, "/vault/api/auth-requests/pending", "device login: bearer pending route")
        r.expect(box.captured?.header("Authorization"), "Bearer approver-bearer", "device login: approver request includes bearer")
        await r.expectThrowsErrorAsync(NetworkingError.accountContextChanged, "device login: stale approver context is denied") {
            _ = try await api.pendingDeviceLoginRequests(accountID: accountID, contextID: UUID())
        }
        box.response = deviceLoginStub(["object": "list", "data": [deviceLoginRecord(), deviceLoginRecord()]])
        await r.expectThrowsErrorAsync(DeviceLoginError.invalidResponse, "device login: duplicate IDs not offered for approval") {
            _ = try await api.pendingDeviceLoginRequests(accountID: accountID, contextID: contextID)
        }

        box.response = deviceLoginStub(deviceLoginRecord())
        let detail = try await api.deviceLoginRequest(id: request.id, accountID: accountID, contextID: contextID)
        r.expect(detail, pending.first, "device login: approver can re-read the pending record")
        r.expect(box.captured?.path, deviceLoginPath, "device login: bearer detail route")
        box.response = deviceLoginStub(deviceLoginRecord(approved: true, answered: true, key: deviceLoginWrappedKey.stringValue))
        let updated = try await api.respondToDeviceLoginRequest(id: request.id, accountID: accountID, contextID: contextID,
                                                               decision: .approve(deviceLoginWrappedKey))
        r.expect(updated.key, deviceLoginWrappedKey, "device login: approval acknowledges the exact encrypted key")
        r.expect(box.captured?.method, "PUT", "device login: responder uses PUT")
        r.expect(box.captured?.path, deviceLoginPath, "device login: bearer response uses UUID route")
        let approveBody = try JSONSerialization.jsonObject(with: box.captured?.body ?? Data()) as? [String: Any] ?? [:]
        r.expect(Set(approveBody.keys), Set(["deviceIdentifier", "key", "requestApproved"]),
                 "device login: approval sends current device and wrapped user key, not a master password hash")
        r.expect(approveBody["deviceIdentifier"] as? String, Fixtures.device.identifier, "device login: approver sends its own device identifier")
        r.expect(approveBody["requestApproved"] as? Bool, true, "device login: approve sets requestApproved")
        r.expect(approveBody["key"] as? String, deviceLoginWrappedKey.stringValue, "device login: approval key uses type 4 wire format")
        let responsesSent = box.capturedCount
        await r.expectThrowsErrorAsync(DeviceLoginError.invalidWrappedKey, "device login: approval refuses a non-type-4 key") {
            _ = try await api.respondToDeviceLoginRequest(id: request.id, accountID: accountID, contextID: contextID,
                                                         decision: .approve(Fixtures.enc()))
        }
        r.expect(box.capturedCount, responsesSent, "device login: invalid approval never dispatched")

        box.response = deviceLoginStub(deviceLoginRecord(answered: true))
        let denied = try await api.respondToDeviceLoginRequest(id: request.id, accountID: accountID, contextID: contextID, decision: .deny)
        r.expect(denied.requestApproved, nil, "device login: Vaultwarden denial returns null approval")
        r.expect(denied.isPending, false, "device login: denial is answered, not pending")
        let denyBody = try JSONSerialization.jsonObject(with: box.captured?.body ?? Data()) as? [String: Any]
        r.expect(denyBody?["requestApproved"] as? Bool, false, "device login: denial explicitly rejects")
        r.expect(denyBody?["key"] as? String, "", "device login: denial sends mandatory but empty key")
    } catch {
        // The fixture contains an attempt credential; don't print raw transport errors.
        r.expectTrue(false, "device login: stubbed transport flow completed")
    }
}
