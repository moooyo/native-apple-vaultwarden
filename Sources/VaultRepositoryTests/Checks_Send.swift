import AppShared
import CryptoCore
import Foundation
import Networking
import os
import VaultModels
import VaultRepository
import VaultStore

func checkSendShareLinks(_ runner: inout TestRunner) {
    let base = URL(string: "https://vault.example.test:8443/passwords/vault")!
    let accessID = "ct2APRQtJk-BLLDwAYqhRA"
    let seed = Data(base64Encoded: "Pgui0FK85cNhBGWHAlBHBw==")!
    do {
        let link = try SendRepository.shareURL(base: base, accessID: accessID, secret: seed)
        runner.expect(link.absoluteString, "https://vault.example.test:8443/passwords/vault/#/send/ct2APRQtJk-BLLDwAYqhRA/Pgui0FK85cNhBGWHAlBHBw",
                      "Send link preserves self-hosted path and contains its key only in the fragment")
        runner.expect(link.query, nil, "Send key is never included in the query")
    } catch {
        runner.expectTrue(false, "Send link fixture: \(error)")
    }
    do {
        _ = try SendRepository.shareURL(base: base, accessID: "?next=/", secret: seed)
        runner.expectTrue(false, "a malformed server access ID cannot become a share link")
    } catch VaultSendError.invalidLink {
        runner.expectTrue(true, "reject unsafe access IDs")
    } catch {
        runner.expectTrue(false, "unexpected Send URL error")
    }
}

private final class SendCacheTransport: URLProtocol, @unchecked Sendable {
    struct Response: Sendable {
        let status: Int
        let body: Data
    }

    static let fixtures = OSAllocatedUnfairLock(initialState: [String: Response]())

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url, let host = url.host, let payload = Self.fixtures.withLock({ $0[host] }) else {
            client?.urlProtocol(self, didFailWithError: URLError(.notConnectedToInternet))
            return
        }
        let response = HTTPURLResponse(url: url, statusCode: payload.status, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: payload.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

func checkOfflineSendSnapshots(_ runner: inout TestRunner) async {
    do {
        let harness = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())])
        defer { Fixtures.cleanup(harness.dir) }
        _ = try await harness.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        guard let accountID = await harness.auth.currentSessionLease()?.accountID else {
            runner.expectTrue(false, "offline Send fixture has an unlocked account"); return
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [SendCacheTransport.self]
        let session = URLSession(configuration: configuration)
        let host = Fixtures.server.base.host!
        defer { SendCacheTransport.fixtures.withLock { $0[host] = nil }; session.invalidateAndCancel() }
        let device = DeviceMetadata(type: DeviceMetadata.DeviceType.iOS, identifier: "send-test", name: "Send fixture")
        let api = APIClient(environment: Fixtures.server, session: session, device: device, clientVersion: "1")
        await api.setAccountID(accountID)
        try await api.setAccessToken("send-test", for: accountID)
        let repository = SendRepository(api: api, store: harness.store, keyVault: harness.keyVault, encryptor: UserKeyEncryptor(), auth: harness.auth)

        let secret = Data(0..<16)
        let contentKey = try SendCryptography.contentKey(secret: secret)
        let wrappedKey = try SymmetricCrypto.encrypt(secret, using: Fixtures.userKey()).stringValue
        let encryptedName = try SymmetricCrypto.encrypt(Data("Send list fixture".utf8), using: contentKey).stringValue
        func wireRecord(_ id: String) -> String {
            """
            {"id":"\(id)","accessId":"AAAAAAAAAAAAAAAAAAAAAA","type":0,"key":"\(wrappedKey)","name":"\(encryptedName)",
             "text":{"hidden":true},"accessCount":0,"disabled":false,"revisionDate":"2020-01-01T00:00:00Z","deletionDate":"2999-01-01T00:00:00Z"}
            """
        }
        func serve(_ rows: [String], status: Int = 200) {
            SendCacheTransport.fixtures.withLock { $0[host] = .init(status: status, body: Data("{\"data\":[\(rows.joined(separator: ","))]}".utf8)) }
        }
        func disconnect() { SendCacheTransport.fixtures.withLock { $0[host] = nil } }
        let single = try VaultJSON.decoder().decode(SendResponse.self, from: Data(wireRecord("second").utf8))
        try await harness.store.setSyncState(.init(accountID: accountID, lastFullSyncAt: "2026-01-01T00:00:00Z"))
        await runner.expectThrowsErrorAsync(NetworkingError.serverUnreachable, "general sync alone cannot supply an offline Send listing") {
            _ = try await repository.listSends()
        }
        try await harness.store.cacheSends([single], accountID: accountID, update: .partialListing)
        try await harness.store.cacheSends([single], accountID: accountID, update: .mutation)
        await runner.expectThrowsErrorAsync(NetworkingError.serverUnreachable, "partial records plus a confirmed item are still not a complete Send list") {
            _ = try await repository.listSends()
        }

        serve([])
        runner.expect(try await repository.listSends().count, 0, "a complete empty online listing succeeds")
        disconnect()
        runner.expect(try await repository.listSends().count, 0, "a confirmed empty cache is available offline")
        serve([wireRecord("first")])
        runner.expect(try await repository.listSends().map(\.id), ["first"], "online Send list replaces its previous complete snapshot")
        disconnect()
        runner.expect(try await repository.listSends().map(\.name), ["Send list fixture"], "a complete populated cache decrypts offline")
        try await harness.store.cacheSends([single], accountID: accountID, update: .mutation)
        runner.expect(try await repository.listSends().map(\.id).sorted(), ["first", "second"], "a confirmed write preserves a complete offline listing")
        try await harness.store.evictSend(id: "first", accountID: accountID)
        runner.expect(try await repository.listSends().map(\.id), ["second"], "a confirmed deletion maintains the full cache")

        let other = "separate-send-account"
        try await harness.store.upsertAccounts([.init(id: other)])
        try await harness.store.cacheSends([single], accountID: other, update: .completeListing)
        for status in [401, 403] {
            let expected = status == 401 ? NetworkingError.unauthorized : .http(status: 403, body: "Send request rejected")
            for _ in 0..<2 {
                serve([], status: status)
                await runner.expectThrowsErrorAsync(expected, "explicit \(status) denies the Send listing") { _ = try await repository.listSends() }
            }
            disconnect()
            await runner.expectThrowsErrorAsync(NetworkingError.serverUnreachable, "offline retry after \(status) cannot restore previously authorized Sends") {
                _ = try await repository.listSends()
            }
            runner.expect(try await harness.store.completeCachedSends(accountID: other)?.map(\.id), ["second"], "revocation affects only its account")
            try await harness.store.cacheSends([single], accountID: accountID, update: .mutation)
            await runner.expectThrowsErrorAsync(NetworkingError.serverUnreachable, "a single successful write cannot reauthorize a rejected listing") {
                _ = try await repository.listSends()
            }
            serve([wireRecord("second")])
            runner.expect(try await repository.listSends().map(\.id), ["second"], "a fresh authorized full list restores Send access")
            disconnect()
            runner.expect(try await repository.listSends().map(\.id), ["second"], "ordinary offline access resumes after fresh authorization")
        }
        await harness.auth.lock()
        await runner.expectThrowsErrorAsync(RepositoryError.locked, "a locked session cannot read a complete Send cache") { _ = try await repository.listSends() }
        try await harness.auth.unlockWithMasterPassword(Fixtures.password)
        runner.expect(try await repository.listSends().map(\.id), ["second"], "unlock restores offline access to the same account")
        await harness.auth.logout()
        runner.expect(try await harness.store.completeCachedSends(accountID: accountID)?.count, nil, "logout discards the account's offline Send snapshot")
        await runner.expectThrowsErrorAsync(RepositoryError.notAuthenticated, "a signed-out session cannot read Sends") { _ = try await repository.listSends() }
    } catch {
        runner.expectTrue(false, "offline Send snapshot fixture: \(error)")
    }
}
