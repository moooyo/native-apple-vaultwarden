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
    // Create
    do {
        let box = StubBox(response: .json(Fixtures.cipher()))
        let client = Fixtures.client(box: box)
        await client.setAccessToken("TOK")
        let req = CipherRequest(type: 1, name: Fixtures.enc(seed: 10),
                                login: CipherLoginRequest(username: Fixtures.enc(seed: 12),
                                                          password: Fixtures.enc(seed: 13)))
        let resp = try await client.createCipher(req)
        r.expect(resp.id, "cipher-99", "createCipher decodes response id")

        guard let cap = box.captured else {
            r.expectTrue(false, "createCipher captured request"); return
        }
        r.expect(cap.method, "POST", "createCipher is POST")
        r.expect(cap.path, "/api/ciphers", "createCipher path")
        r.expect(cap.header("Authorization"), "Bearer TOK", "createCipher Bearer header")
        // The body encodes EncString fields as wire strings.
        if let obj = try? JSONSerialization.jsonObject(with: cap.body ?? Data()) as? [String: Any] {
            r.expect(obj["name"] as? String, Fixtures.validEnc(seed: 10),
                     "createCipher body name is EncString wire string")
            r.expect(obj["type"] as? Int, 1, "createCipher body type")
            let login = obj["login"] as? [String: Any]
            r.expect(login?["username"] as? String, Fixtures.validEnc(seed: 12),
                     "createCipher body login.username EncString")
        } else {
            r.expectTrue(false, "createCipher body is JSON object")
        }
    } catch {
        r.expectTrue(false, "createCipher threw: \(error)")
    }

    // Update
    do {
        let box = StubBox(response: .json(Fixtures.cipher()))
        let client = Fixtures.client(box: box)
        await client.setAccessToken("TOK")
        let req = CipherRequest(type: 1, name: Fixtures.enc(seed: 10))
        _ = try await client.updateCipher(id: "cipher-99", req)
        r.expect(box.captured?.method, "PUT", "updateCipher is PUT")
        r.expect(box.captured?.path, "/api/ciphers/cipher-99", "updateCipher path")
    } catch {
        r.expectTrue(false, "updateCipher threw: \(error)")
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
