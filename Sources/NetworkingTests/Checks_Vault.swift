import Foundation
import Networking
import VaultModels
import CryptoCore

func checkSync(_ r: inout TestRunner) async {
    let box = StubBox(response: .json(Fixtures.sync()))
    let client = Fixtures.client(box: box)
    await client.setAccessToken("ACCESS-TOKEN-XYZ")

    do {
        let resp = try await client.sync(excludeDomains: true)
        r.expect(resp.profile.id, "user-1", "sync profile id")
        r.expect(resp.ciphers.count, 1, "sync ciphers count")
        r.expect(resp.ciphers.first?.id, "cipher-1", "sync cipher id")
        r.expect(resp.folders.count, 1, "sync folders count")
        r.expect(resp.droppedCipherErrors.count, 0, "sync no dropped ciphers")
    } catch {
        r.expectTrue(false, "sync threw: \(error)")
    }

    guard let cap = box.captured else {
        r.expectTrue(false, "sync captured a request"); return
    }
    r.expect(cap.method, "GET", "sync is GET")
    r.expect(cap.path, "/api/sync", "sync path")
    r.expect(cap.header("Authorization"), "Bearer ACCESS-TOKEN-XYZ", "sync Bearer header")
    r.expectTrue(cap.url.query?.contains("excludeDomains=true") ?? false,
                 "sync excludeDomains query")
}

func checkAccountScopedVaultRequests(_ r: inout TestRunner) async {
    let box = StubBox(response: .json(Fixtures.sync()))
    let client = Fixtures.client(box: box)
    await client.setAccountID("account-a")
    do { try await client.setAccessToken("TOKEN-A", for: "account-a") }
    catch { r.expectTrue(false, "account lease setup threw: \(error)"); return }

    await r.expectThrowsErrorAsync(
        NetworkingError.accountContextChanged,
        "account lease: mismatched request is rejected locally"
    ) {
        _ = try await client.sync(accountID: "account-b", excludeDomains: true)
    }
    r.expectTrue(box.captured == nil,
                 "account lease: mismatch builds/sends no URLRequest")

    do {
        _ = try await client.sync(accountID: "account-a", excludeDomains: true)
        r.expect(box.captured?.header("Authorization"), "Bearer TOKEN-A",
                 "account lease: matching request uses bound bearer")
    } catch {
        r.expectTrue(false, "account lease matching request threw: \(error)")
    }

    await client.setEnvironment(
        ServerEnvironment(string: "https://other.example.test")!
    )
    await client.setAccountID("account-b")
    do { try await client.setAccessToken("TOKEN-B", for: "account-b") }
    catch { r.expectTrue(false, "account lease B setup threw: \(error)") }
    await r.expectThrowsErrorAsync(
        NetworkingError.accountContextChanged,
        "account lease: stale refresh cannot install A bearer on B"
    ) {
        try await client.setAccessToken("STALE-A", for: "account-a")
    }
    r.expect(await client.currentAccessToken(), "TOKEN-B",
             "account lease: stale setter preserves B bearer")
}

func checkCipherVisibilityRequests(_ runner: inout TestRunner) async {
    let box = StubBox(response: .json(Fixtures.cipher()))
    let client = Fixtures.client(box: box)
    await client.setAccountID("personal")
    do {
        try await client.setAccessToken("TOKEN", for: "personal")
        for change in [CipherVisibilityChange.archive, .unarchive, .restore, .trash] {
            if change == .trash { box.response = StubResponse(statusCode: 200) }
            let result = try await client.changeCipherVisibility(accountID: "personal", id: "cipher-1", change: change)
            runner.expect(result == nil, change == .trash, "only soft delete has no response body")
            runner.expect(box.captured?.method, "PUT", "a visibility change is never permanent deletion")
            runner.expect(box.captured?.path, "/api/ciphers/cipher-1/\(change.rawValue)", "uses the visibility action endpoint")
            runner.expect(box.captured?.header("Authorization"), "Bearer TOKEN", "uses the matching account bearer")
        }
        await runner.expectThrowsErrorAsync(NetworkingError.accountContextChanged, "rejects wrong-account visibility mutation") {
            _ = try await client.changeCipherVisibility(accountID: "other", id: "cipher-1", change: .trash)
        }
    } catch { runner.expectTrue(false, "visibility request failed: \(error)") }
}

/// A request that was valid when sent must still be discarded if its account context changes
/// while URLSession is suspended. Switching A -> B -> A specifically proves this is a lease
/// generation check, not only a final account-id equality check.
func checkInFlightAccountLeaseRevocation(_ r: inout TestRunner) async {
    let box = StubBox(response: .json(Fixtures.sync()))
    box.pauseResponses()
    let client = Fixtures.client(box: box)
    await client.setAccountID("account-a")
    do { try await client.setAccessToken("TOKEN-A-OLD", for: "account-a") }
    catch {
        box.resumeResponses()
        r.expectTrue(false, "in-flight lease setup threw: \(error)")
        return
    }

    let oldRequest = Task { () -> NetworkingError? in
        do {
            _ = try await client.sync(accountID: "account-a", excludeDomains: true)
            return nil
        } catch let error as NetworkingError {
            return error
        } catch {
            return .transport(String(describing: error))
        }
    }

    var requestWasSent = false
    for _ in 0..<10_000 {
        if box.captured != nil {
            requestWasSent = true
            break
        }
        await Task.yield()
    }
    guard requestWasSent else {
        box.resumeResponses()
        _ = await oldRequest.value
        r.expectTrue(false, "in-flight lease: request reached URLProtocol")
        return
    }
    r.expect(box.captured?.header("Authorization"), "Bearer TOKEN-A-OLD",
             "in-flight lease: request left with old bearer")

    await client.setEnvironment(ServerEnvironment(string: "https://other.example.test")!)
    await client.setAccountID("account-b")
    try? await client.setAccessToken("TOKEN-B", for: "account-b")
    await client.setEnvironment(Fixtures.environment())
    await client.setAccountID("account-a")
    try? await client.setAccessToken("TOKEN-A-NEW", for: "account-a")

    box.resumeResponses()
    r.expect(await oldRequest.value, NetworkingError.accountContextChanged,
             "in-flight lease: A-B-A switch rejects old response")
    r.expect(await client.currentAccessToken(), "TOKEN-A-NEW",
             "in-flight lease: old response cannot disturb new bearer")
}

/// Same-account bearer rotation must not revoke an otherwise valid vault response. Refresh
/// ordering has its own generation; conflating it with account ownership duplicates POSTs.
func checkBearerRotationPreservesAccountLease(_ r: inout TestRunner) async {
    let box = StubBox(response: .json(Fixtures.sync()))
    box.pauseResponses()
    let client = Fixtures.client(box: box)
    await client.setAccountID("account-a")
    try? await client.setAccessToken("TOKEN-OLD", for: "account-a")

    let request = Task { try await client.sync(accountID: "account-a", excludeDomains: true) }
    for _ in 0..<10_000 {
        if box.captured != nil { break }
        await Task.yield()
    }
    do {
        try await client.setAccessToken("TOKEN-NEW", for: "account-a")
    } catch {
        box.resumeResponses()
        _ = try? await request.value
        r.expectTrue(false, "bearer rotation setup threw: \(error)")
        return
    }
    box.resumeResponses()
    do {
        r.expect(try await request.value.profile.id, "user-1",
                 "same-account bearer rotation accepts in-flight response")
        r.expect(await client.currentAccessToken(), "TOKEN-NEW",
                 "same-account bearer rotation keeps new token")
    } catch {
        r.expectTrue(false, "same-account bearer rotation rejected response: \(error)")
    }
}

func checkHeaderInjection(_ r: inout TestRunner) async {
    let box = StubBox(response: .json(Fixtures.config))
    let client = Fixtures.client(box: box)

    _ = try? await client.config()
    guard let cap = box.captured else {
        r.expectTrue(false, "header injection captured a request"); return
    }
    r.expect(cap.header("Device-Type"), "1", "Device-Type header")
    r.expect(cap.header("Bitwarden-Client-Name"), "mobile", "Bitwarden-Client-Name header")
    r.expect(cap.header("Bitwarden-Client-Version"), Fixtures.clientVersion,
             "Bitwarden-Client-Version header")
    r.expect(cap.header("Device-Identifier"), "DEV-IDENT-UUID", "Device-Identifier header")
}

func checkCipherCRUD(_ r: inout TestRunner) async {
    do {
        let box = StubBox(response: .json(Fixtures.sync()))
        let client = Fixtures.client(box: box)
        let accountID = "https://vault.example.test|throwaway@example.test"
        await client.setAccountID(accountID)
        try await client.setAccessToken("TOK", for: accountID)
        _ = try await client.sync(accountID: accountID, excludeDomains: true)
        box.response = .json(Fixtures.cipher())
        let req = CipherRequest(type: 1, name: Fixtures.enc(seed: 10),
                                login: CipherLoginRequest(username: Fixtures.enc(seed: 12),
                                                          password: Fixtures.enc(seed: 13)))
        let resp = try await client.createCipher(accountID: accountID, req)
        r.expect(resp.id, "cipher-99", "createCipher decodes response id")

        guard let cap = box.captured else {
            r.expectTrue(false, "createCipher captured request"); return
        }
        r.expect(cap.method, "POST", "createCipher is POST")
        r.expect(cap.path, "/api/ciphers", "createCipher path")
        r.expect(cap.header("Authorization"), "Bearer TOK", "createCipher Bearer header")
        // The body encodes EncString fields as wire strings.
        if let obj = try? JSONSerialization.jsonObject(with: cap.body ?? Data()) as? [String: Any] {
            r.expect(obj["encryptedFor"] as? String, "user-1", "createCipher uses sync profile id, not local account id")
            r.expect(obj["name"] as? String, Fixtures.validEnc(seed: 10),
                     "createCipher body name is EncString wire string")
            r.expect(obj["type"] as? Int, 1, "createCipher body type")
            let login = obj["login"] as? [String: Any]
            r.expect(login?["username"] as? String, Fixtures.validEnc(seed: 12),
                     "createCipher body login.username EncString")
        } else {
            r.expectTrue(false, "createCipher body is JSON object")
        }
        box.response = .json(Fixtures.token())
        _ = try await client.refresh(refreshToken: "REFRESH", server: Fixtures.environment(), accountID: accountID)
        box.response = .json(Fixtures.cipher())
        _ = try await client.updateCipher(accountID: accountID, id: "cipher-99", req)
        r.expect(box.captured?.method, "PUT", "updateCipher is PUT")
        r.expect(box.captured?.path, "/api/ciphers/cipher-99", "updateCipher path")
        r.expect(box.captured?.header("Authorization"), "Bearer AT-123", "cipher update uses the rotated bearer")
        let update = try JSONSerialization.jsonObject(with: box.captured?.body ?? Data()) as? [String: Any]
        r.expect(update?["encryptedFor"] as? String, "user-1", "updateCipher keeps same-account server user id after refresh")

        try await client.setAccessToken(nil, for: accountID)
        try await client.setAccessToken("SAME-SCOPE", for: accountID)
        box.response = .json(#"{"id":" "}"#)
        await r.expectThrowsErrorAsync(NetworkingError.decoding("Missing server user ID"),
                                       "a revoked bearer cannot leave an authorized profile behind") {
            _ = try await client.updateCipher(accountID: accountID, id: "cipher-99", req)
        }
        r.expect(box.captured?.path, "/api/accounts/profile", "explicit bearer revocation requires a fresh profile")

        await client.setAccountID(accountID)
        await r.expectThrowsErrorAsync(NetworkingError.decoding("Missing server user ID"),
                                       "cipher writes reject a missing profile id after rebinding") {
            _ = try await client.updateCipher(accountID: accountID, id: "cipher-99", req)
        }
        r.expect(box.captured?.method, "GET", "cipher writers do not send an update for a missing profile id")
        r.expect(box.captured?.header("Authorization"), nil, "rebinding cannot reuse the previous bearer")
    } catch {
        r.expectTrue(false, "cipher create/update threw: \(error)")
    }

    // Delete
    do {
        let box = StubBox(response: StubResponse(statusCode: 200))
        let client = Fixtures.client(box: box)
        await client.setAccessToken("TOK")
        try await client.deleteCipher(id: "cipher-99")
        r.expect(box.captured?.method, "DELETE", "deleteCipher is DELETE")
        r.expect(box.captured?.path, "/api/ciphers/cipher-99", "deleteCipher path")
    } catch {
        r.expectTrue(false, "deleteCipher threw: \(error)")
    }
}

func checkCipherWriterProfileLookup(_ runner: inout TestRunner) async {
    let profile = #"{"id":"server-owner"}"#
    let box = StubBox(response: .json(Fixtures.cipher()),
                      responsesByPath: ["/api/accounts/profile": .json(profile)])
    let client = Fixtures.client(box: box)
    let accountID = "not-the-server-owner"
    await client.bindAccount(accountID, contextID: UUID())

    do {
        try await client.setAccessToken("COLD-SESSION", for: accountID)
        let payload = CipherRequest(type: 1, name: Fixtures.enc())
        _ = try await client.createCipher(accountID: accountID, payload)
        runner.expect(box.captured?.method, "POST", "a cold session proceeds to write after resolving its profile")
        runner.expect(box.captured?.header("Authorization"), "Bearer COLD-SESSION", "cold-session write uses the account bearer")
        let body = try JSONSerialization.jsonObject(with: box.captured?.body ?? Data()) as? [String: Any]
        runner.expect(body?["encryptedFor"] as? String, "server-owner", "cipher creation before any sync resolves the server profile id")
    } catch {
        runner.expectTrue(false, "cipher creation before sync threw: \(error)")
    }
}

func checkCipherProfileLookupLeaseRevocation(_ runner: inout TestRunner) async {
    let box = StubBox(response: .json(#"{"id":"old-owner"}"#))
    let client = Fixtures.client(box: box)
    let accountID = "same-local-account"
    await client.bindAccount(accountID, contextID: UUID())
    await client.setAccessToken("OLD")
    box.pauseResponses()
    let write = Task {
        try await client.createCipher(accountID: accountID, CipherRequest(type: 1, name: Fixtures.enc()))
    }

    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while box.captured == nil && ContinuousClock.now < deadline {
        try? await Task.sleep(for: .milliseconds(10))
    }
    runner.expect(box.captured?.path, "/api/accounts/profile", "cipher write starts with the server profile lookup")
    runner.expect(box.captured?.header("Authorization"), "Bearer OLD", "profile lookup uses the original bearer")
    await client.bindAccount("other-local-account", contextID: UUID())
    runner.expect(await client.currentAccessToken(), nil, "binding another account clears the old bearer without an environment change")
    await client.bindAccount(accountID, contextID: UUID())
    await client.setAccessToken("NEW")
    box.captured = nil
    box.resumeResponses()

    await runner.expectThrowsErrorAsync(NetworkingError.accountContextChanged,
                                        "a revoked profile lookup does not authorize a write in the new session") {
        _ = try await write.value
    }
    runner.expectTrue(box.captured == nil, "a stale cipher owner does not send a POST")

    box.response = .json(#"{"id":""}"#)
    await runner.expectThrowsErrorAsync(NetworkingError.decoding("Missing server user ID"),
                                        "old profile does not populate the new session's owner cache") {
        _ = try await client.createCipher(accountID: accountID, CipherRequest(type: 1, name: Fixtures.enc()))
    }
    runner.expect(box.captured?.header("Authorization"), "Bearer NEW", "new profile lookup uses only its own bearer")
}

func checkCipherCreateAcknowledgment(_ runner: inout TestRunner) async {
    let box = StubBox(response: .json(Fixtures.sync()))
    let client = Fixtures.client(box: box)
    let accountID = "create-account"
    await client.setAccountID(accountID)
    await client.setAccessToken("CREATE")
    do { _ = try await client.sync(accountID: accountID, excludeDomains: true) }
    catch { runner.expectTrue(false, "create acknowledgment setup failed: \(error)"); return }

    let payload = CipherRequest(type: 1, name: Fixtures.enc())
    let uncertainResponses: [(String, StubResponse)] = [
        ("timeout", StubResponse(delivery: .failure(.timedOut))),
        ("lost connection", StubResponse(delivery: .failure(.networkConnectionLost))),
        ("cancellation after dispatch", StubResponse(delivery: .failure(.cancelled))),
        ("non-HTTP response", StubResponse(delivery: .nonHTTP)),
        ("malformed acknowledgment", .json("{}")),
        ("empty response ID", .json(Fixtures.cipher().replacingOccurrences(of: "cipher-99", with: ""))),
        ("temporary redirect", StubResponse(statusCode: 307, headers: ["Location": "https://vault.example.test/other"])),
        ("possible partial commit", .json("Error saving cipher", status: 400)),
        ("HTTP request timeout", .json("upstream timeout", status: 408)),
        ("upstream failure", .json("proxy error", status: 502)),
    ]
    for (label, response) in uncertainResponses {
        box.response = response
        let before = box.capturedCount
        await runner.expectThrowsErrorAsync(NetworkingError.cipherCreateUnconfirmed, "create: \(label) leaves delivery unconfirmed") {
            _ = try await client.createCipher(accountID: accountID, payload)
        }
        runner.expect(box.capturedCount, before + 1, "create: \(label) does not resend the POST")
        runner.expect(box.captured?.path, "/api/ciphers", "create: \(label) remains scoped to the original path")
    }

    for error: URLError.Code in [.cannotFindHost, .cannotConnectToHost, .dnsLookupFailed, .notConnectedToInternet] {
        box.response = StubResponse(delivery: .failure(error))
        await runner.expectThrowsErrorAsync(NetworkingError.serverUnreachable, "create: \(error) is a pre-connect failure") {
            _ = try await client.createCipher(accountID: accountID, payload)
        }
    }

    box.response = .json("invalid item", status: 422)
    await runner.expectThrowsErrorAsync(NetworkingError.http(status: 422, body: "invalid item"), "create: definite HTTP rejection is preserved") {
        _ = try await client.createCipher(accountID: accountID, payload)
    }
    box.response = .json("expired", status: 401)
    await runner.expectThrowsErrorAsync(NetworkingError.unauthorized, "create: expired authentication can still be refreshed") {
        _ = try await client.createCipher(accountID: accountID, payload)
    }
    box.response = StubResponse(delivery: .failure(.timedOut))
    await runner.expectThrowsErrorAsync(NetworkingError.serverUnreachable, "update: timeout retains the normal transport mapping") {
        _ = try await client.updateCipher(accountID: accountID, id: "cipher-99", payload)
    }
    box.response = .json("proxy error", status: 502)
    await runner.expectThrowsErrorAsync(NetworkingError.http(status: 502, body: "proxy error"), "update: server rejection is not a create uncertainty") {
        _ = try await client.updateCipher(accountID: accountID, id: "cipher-99", payload)
    }

    let coldBox = StubBox(response: StubResponse(delivery: .failure(.timedOut)))
    let coldClient = Fixtures.client(box: coldBox)
    await coldClient.setAccountID(accountID)
    await coldClient.setAccessToken("COLD")
    await runner.expectThrowsErrorAsync(NetworkingError.serverUnreachable, "create: profile lookup timeout is not a submitted POST") {
        _ = try await coldClient.createCipher(accountID: accountID, payload)
    }
    runner.expect(coldBox.capturedCount, 1, "create: failed profile setup sends only one request")
    runner.expect(coldBox.captured?.path, "/api/accounts/profile", "create: no POST is sent after failed profile lookup")
}

func checkCipherCreateDispatchLeaseRevocation(_ runner: inout TestRunner) async {
    let box = StubBox(response: .json(Fixtures.cipher()),
                      responsesByPath: ["/api/accounts/profile": .json(#"{"id":"owner"}"#)])
    let client = Fixtures.client(box: box)
    let accountID = "old-create-session"
    await client.bindAccount(accountID, contextID: UUID())
    await client.setAccessToken("OLD")
    let payload = CipherRequest(type: 1, name: Fixtures.enc())
    do { _ = try await client.createCipher(accountID: accountID, payload) }
    catch { runner.expectTrue(false, "create lease setup failed: \(error)"); return }

    box.captured = nil
    box.response = StubResponse(delivery: .failure(.networkConnectionLost))
    box.pauseResponses()
    let staleWrite = Task { try await client.createCipher(accountID: accountID, payload) }
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while box.captured == nil && ContinuousClock.now < deadline {
        try? await Task.sleep(for: .milliseconds(10))
    }
    runner.expect(box.captured?.method, "POST", "create lease: dispatched the original POST")
    runner.expect(box.captured?.header("Authorization"), "Bearer OLD", "create lease: the dispatched request is anchored to the old bearer")
    await client.bindAccount(accountID, contextID: UUID())
    await client.setAccessToken("NEW")
    box.resumeResponses()
    await runner.expectThrowsErrorAsync(NetworkingError.accountContextChanged, "create lease: stale failure cannot publish into a replacement session") {
        _ = try await staleWrite.value
    }
    runner.expect(await client.currentAccessToken(), "NEW", "create lease: the replacement bearer remains unchanged")
}

func checkFolders(_ r: inout TestRunner) async {
    // List
    do {
        let box = StubBox(response: .json(Fixtures.folderListJSON()))
        let client = Fixtures.client(box: box)
        await client.setAccessToken("TOK")
        let folders = try await client.folders()
        r.expect(folders.count, 2, "folders list count (unwraps {data:[...]})")
        r.expect(folders.first?.id, "folder-1", "folders list first id")
        r.expect(box.captured?.method, "GET", "folders is GET")
        r.expect(box.captured?.path, "/api/folders", "folders path")
    } catch {
        r.expectTrue(false, "folders threw: \(error)")
    }

    // Create
    do {
        let box = StubBox(response: .json(Fixtures.folder()))
        let client = Fixtures.client(box: box)
        await client.setAccessToken("TOK")
        let resp = try await client.createFolder(FolderRequest(name: Fixtures.enc(seed: 5)))
        r.expect(resp.id, "folder-99", "createFolder decodes id")
        r.expect(box.captured?.method, "POST", "createFolder is POST")
        if let obj = try? JSONSerialization.jsonObject(with: box.captured?.body ?? Data()) as? [String: Any] {
            r.expect(obj["name"] as? String, Fixtures.validEnc(seed: 5),
                     "createFolder body name EncString wire string")
        } else {
            r.expectTrue(false, "createFolder body is JSON object")
        }
    } catch {
        r.expectTrue(false, "createFolder threw: \(error)")
    }

    // Update
    do {
        let box = StubBox(response: .json(Fixtures.folder()))
        let client = Fixtures.client(box: box)
        await client.setAccessToken("TOK")
        _ = try await client.updateFolder(id: "folder-99", FolderRequest(name: Fixtures.enc(seed: 6)))
        r.expect(box.captured?.method, "PUT", "updateFolder is PUT")
        r.expect(box.captured?.path, "/api/folders/folder-99", "updateFolder path")
    } catch {
        r.expectTrue(false, "updateFolder threw: \(error)")
    }

    // Delete
    do {
        let box = StubBox(response: StubResponse(statusCode: 200))
        let client = Fixtures.client(box: box)
        await client.setAccessToken("TOK")
        try await client.deleteFolder(id: "folder-99")
        r.expect(box.captured?.method, "DELETE", "deleteFolder is DELETE")
        r.expect(box.captured?.path, "/api/folders/folder-99", "deleteFolder path")
    } catch {
        r.expectTrue(false, "deleteFolder threw: \(error)")
    }
}

func checkAttachments(_ r: inout TestRunner) async {
    // Step 1: request upload URL
    do {
        let box = StubBox(response: .json(Fixtures.attachmentUpload()))
        let client = Fixtures.client(box: box)
        await client.setAccessToken("TOK")
        let req = AttachmentRequest(key: Fixtures.enc(seed: 30),
                                    fileName: Fixtures.enc(seed: 31),
                                    fileSize: 4096)
        let resp = try await client.attachmentUploadURL(cipherID: "cipher-1", req)
        r.expect(resp.attachmentId, "att-1", "attachment step1 attachmentId")
        r.expect(resp.fileUploadType, 0, "attachment step1 fileUploadType direct")
        r.expect(box.captured?.method, "POST", "attachment step1 is POST")
        r.expect(box.captured?.path, "/api/ciphers/cipher-1/attachment/v2",
                 "attachment step1 path")
        if let obj = try? JSONSerialization.jsonObject(with: box.captured?.body ?? Data()) as? [String: Any] {
            r.expect(obj["key"] as? String, Fixtures.validEnc(seed: 30),
                     "attachment step1 body key EncString")
            r.expect(obj["fileName"] as? String, Fixtures.validEnc(seed: 31),
                     "attachment step1 body fileName EncString")
            r.expect(obj["fileSize"] as? Int, 4096, "attachment step1 body fileSize")
        } else {
            r.expectTrue(false, "attachment step1 body is JSON object")
        }

        // Step 2: upload the encrypted blob to the returned (local) URL.
        let box2 = StubBox(response: StubResponse(statusCode: 201))
        let client2 = Fixtures.client(box: box2)
        await client2.setAccessToken("TOK")
        try await client2.uploadAttachment(to: resp.url, cipherID: "cipher-1",
                                            attachmentID: resp.attachmentId,
                                            encryptedData: Data([1, 2, 3, 4]))
        r.expect(box2.captured?.method, "POST", "attachment step2 (direct) is POST")
        r.expectTrue(box2.captured?.header("Content-Type")?.contains("multipart/form-data") ?? false,
                     "attachment step2 multipart Content-Type")
        r.expectTrue(box2.captured?.bodyString.contains("name=\"data\"") ?? false,
                     "attachment step2 multipart has data field")
    } catch {
        r.expectTrue(false, "attachment flow threw: \(error)")
    }
}

func checkConfigAndAlive(_ r: inout TestRunner) async {
    // config
    do {
        let box = StubBox(response: .json(Fixtures.config))
        let client = Fixtures.client(box: box)
        let cfg = try await client.config()
        r.expect(cfg.version, "1.32.0", "config decodes version")
        r.expect(cfg.gitHash, "abc1234", "config decodes gitHash")
        r.expect(box.captured?.path, "/api/config", "config path")
    } catch {
        r.expectTrue(false, "config threw: \(error)")
    }

    // alive → true on 200
    do {
        let box = StubBox(response: StubResponse(statusCode: 200, body: Data("ok".utf8)))
        let client = Fixtures.client(box: box)
        let up = try await client.alive()
        r.expectTrue(up, "alive returns true on 200")
        r.expect(box.captured?.method, "GET", "alive is GET")
        r.expect(box.captured?.path, "/alive", "alive path is /alive (NOT under /api)")
    } catch {
        r.expectTrue(false, "alive threw: \(error)")
    }
}

func checkErrorMapping(_ r: inout TestRunner) async {
    // 401 → .unauthorized
    do {
        let box = StubBox(response: StubResponse(statusCode: 401))
        let client = Fixtures.client(box: box)
        await client.setAccessToken("EXPIRED")
        await r.expectThrowsErrorAsync(NetworkingError.unauthorized, "401 maps to .unauthorized") {
            _ = try await client.sync()
        }
    }

    // 500 → .http(status: 500, ...)
    do {
        let box = StubBox(response: StubResponse(statusCode: 500, body: Data("boom".utf8)))
        let client = Fixtures.client(box: box)
        await client.setAccessToken("TOK")
        do {
            _ = try await client.sync()
            r.expectTrue(false, "500 should throw")
        } catch let NetworkingError.http(status, body) {
            r.expect(status, 500, "500 maps to .http with status 500")
            r.expectTrue(body.contains("boom"), "500 carries response body")
        } catch {
            r.expectTrue(false, "500 mapped to wrong error: \(error)")
        }
    }
}

func checkDevicePushNoOp(_ r: inout TestRunner) async {
    // registerDevicePushToken is a documented no-op: it must NOT make a request.
    let box = StubBox(response: StubResponse(statusCode: 200))
    let client = Fixtures.client(box: box)
    await client.setAccessToken("TOK")
    do {
        try await client.registerDevicePushToken("apns-token")
        r.expectTrue(box.captured == nil, "registerDevicePushToken makes no network call (no-op)")
    } catch {
        r.expectTrue(false, "registerDevicePushToken threw: \(error)")
    }
}

func checkServerEnvironment(_ r: inout TestRunner) {
    // Default derivation.
    let env = ServerEnvironment(string: "https://vault.example.test/")!
    r.expect(env.identityBase.absoluteString, "https://vault.example.test/identity",
             "identityBase default derivation (trailing slash trimmed)")
    r.expect(env.apiBase.absoluteString, "https://vault.example.test/api",
             "apiBase default derivation")
    r.expectTrue(ServerEnvironment(string: "https://vault.example.test///") != nil,
                 "ServerEnvironment trims repeated trailing slashes")
    r.expectTrue(ServerEnvironment(string: "http://localhost:8080") != nil,
                 "ServerEnvironment accepts explicit local HTTP")
    r.expectTrue(ServerEnvironment(string: "ftp://vault.example.test") == nil,
                 "ServerEnvironment rejects non-HTTP schemes")
    r.expectTrue(ServerEnvironment(string: "vault.example.test") == nil,
                 "ServerEnvironment rejects a URL without scheme")
    r.expectTrue(ServerEnvironment(string: "https://vault.example.test?x=1") == nil,
                 "ServerEnvironment rejects query components")
    r.expectTrue(ServerEnvironment(string: "https://vault.example.test/#fragment") == nil,
                 "ServerEnvironment rejects fragment components")
    r.expectTrue(ServerEnvironment(string: "https://user:secret@vault.example.test") == nil,
                 "ServerEnvironment rejects credentials that would be persisted in a URL")
    // aliveURL is module-internal; its derivation is asserted end-to-end in
    // checkConfigAndAlive via the captured request path (/alive, not /api/alive).

    // Split URLs.
    let split = ServerEnvironment(base: URL(string: "https://vault.example.test")!,
                                  identityURL: URL(string: "https://identity.example.test")!,
                                  apiURL: URL(string: "https://api.example.test")!)
    r.expect(split.identityBase.absoluteString, "https://identity.example.test",
             "identityBase override")
    r.expect(split.apiBase.absoluteString, "https://api.example.test", "apiBase override")
}
