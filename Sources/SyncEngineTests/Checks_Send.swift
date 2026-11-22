import Foundation
import Networking
import SyncEngine

func checkSendSyncCache(_ runner: inout TestRunner) async {
    guard let (store, directory) = try? Fixtures.freshStore() else {
        runner.expectTrue(false, "Send cache fixture store"); return
    }
    defer { Fixtures.cleanup(directory) }
    let encryptedName = Fixtures.enc("Send cache fixture")
    let record = """
    {"id":"send-one","accessId":"ct2APRQtJk-BLLDwAYqhRA","type":0,"name":"\(encryptedName)",
    "key":"\(Fixtures.enc("synthetic data"))","text":{"hidden":false},"accessCount":0,"disabled":false,
    "revisionDate":"2026-01-01T00:00:00.460Z","deletionDate":"2026-01-10T00:00:00Z"}
    """
    let empty = Fixtures.syncJSON(ciphers: [])
    func payload(_ contents: String) -> String { empty.replacingOccurrences(of: "\"sends\":[]", with: "\"sends\":[\(contents)]") }
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(payload(record)))
    let engine = SyncEngine(api: api, store: store, keyVault: await Fixtures.unlockedVault(),
                            identityStore: FakeIdentityStore(enabled: false))
    do {
        await api.setSyncResponse(Fixtures.decodeSync(empty.replacingOccurrences(of: "\"sends\":[]", with: "\"sends\":null")))
        _ = try await engine.fullSync(accountID: Fixtures.accountID)
        runner.expectTrue(try await store.syncState(accountID: Fixtures.accountID) != nil, "a vault sync can finish without a Send snapshot")
        runner.expect(try await store.completeCachedSends(accountID: Fixtures.accountID)?.count, nil, "general sync is not proof of an empty offline Send list")
        await api.setSyncResponse(Fixtures.decodeSync(payload(record + ",{}")))
        runner.expect(try await engine.fullSync(accountID: Fixtures.accountID).sendCount, nil, "an initial partial listing cannot publish a count")
        runner.expect(try await store.completeCachedSends(accountID: Fixtures.accountID)?.count, nil, "initial partial records cannot certify the offline collection")
        await api.setSyncResponse(Fixtures.decodeSync(payload(record)))
        _ = try await engine.fullSync(accountID: Fixtures.accountID)
        let stored = try await store.completeCachedSends(accountID: Fixtures.accountID) ?? []
        runner.expect(stored.first?.name.stringValue, encryptedName, "Send cache contains original ciphertext")
        runner.expect(try await store.completeCachedSends(accountID: "other")?.count, nil, "Send snapshot completeness is account-scoped")
        let snapshot = try await store.sendCacheGeneration(accountID: Fixtures.accountID)
        try await store.evictSend(id: "send-one", accountID: Fixtures.accountID)
        let stale = try await store.cacheSends(stored, accountID: Fixtures.accountID, update: .completeListing, ifUnchangedSince: snapshot)
        runner.expect(stale, nil, "a superseded listing cannot publish an authoritative Send count")
        runner.expect(try await store.completeCachedSends(accountID: Fixtures.accountID)?.count, 0,
                      "sync captured before deletion cannot reinsert a disabled reservation")
        let precedingUpload = try await store.sendCacheGeneration(accountID: Fixtures.accountID)
        try await store.cacheSends(stored, accountID: Fixtures.accountID, update: .mutation)
        try await store.cacheSends([], accountID: Fixtures.accountID, update: .completeListing, ifUnchangedSince: precedingUpload)
        runner.expect(try await store.completeCachedSends(accountID: Fixtures.accountID)?.count, 1,
                      "stale sync cannot erase the final published upload")
        await api.setSyncResponse(Fixtures.decodeSync(payload("{}")))
        let partial = try await engine.fullSync(accountID: Fixtures.accountID)
        runner.expect(partial.dropped, 1, "malformed Send is reported without aborting vault sync")
        runner.expect(partial.sendCount, nil, "a partially decoded listing has an unknown Send count")
        runner.expect(try await store.completeCachedSends(accountID: Fixtures.accountID)?.count, nil, "a partial refresh cannot certify an earlier complete listing")
        let future = record.replacingOccurrences(of: "2026-01-10", with: "2999-01-10")
        let past = record.replacingOccurrences(of: "send-one", with: "deleted").replacingOccurrences(of: "2026-01-10", with: "2000-01-10")
        let file = future.replacingOccurrences(of: "send-one", with: "disabled-file").replacingOccurrences(of: "\"type\":0", with: "\"type\":1")
            .replacingOccurrences(of: "\"disabled\":false", with: "\"disabled\":true,\"expirationDate\":\"2000-01-01T00:00:00Z\"")
        let unknown = future.replacingOccurrences(of: "send-one", with: "other-kind").replacingOccurrences(of: "\"type\":0", with: "\"type\":99")
        await api.setSyncResponse(Fixtures.decodeSync(payload([future, past, file, unknown].joined(separator: ","))))
        runner.expect(try await engine.fullSync(accountID: Fixtures.accountID).sendCount, 2,
                      "count only supported, undeleted Sends, including expired or disabled records")
        await api.setSyncResponse(Fixtures.decodeSync(empty.replacingOccurrences(of: "\"sends\":[]", with: "\"sends\":null")))
        runner.expect(try await engine.fullSync(accountID: Fixtures.accountID).sendCount, nil, "an unavailable Send snapshot is not zero")
        runner.expect(try await store.completeCachedSends(accountID: Fixtures.accountID)?.count, nil, "an absent Send section cannot certify a stale count")
        await api.setSyncResponse(Fixtures.decodeSync(empty))
        runner.expect(try await engine.fullSync(accountID: Fixtures.accountID).sendCount, 0, "a complete empty Send snapshot reports zero")
        runner.expect(try await store.completeCachedSends(accountID: Fixtures.accountID)?.count, 0, "complete empty Send list clears cache and certifies zero")

        await api.setSyncResponse(Fixtures.decodeSync(payload(future)))
        runner.expect(try await engine.fullSync(accountID: Fixtures.accountID).sendCount, 1, "a complete sync records the populated Send snapshot")
        let concurrentAPI = FakeVaultAPI(syncResponse: Fixtures.decodeSync(payload(future)))
        let concurrentEngine = SyncEngine(api: concurrentAPI, store: store, keyVault: await Fixtures.unlockedVault(), identityStore: FakeIdentityStore(enabled: false))
        await concurrentAPI.pauseNextSync()
        let delayed = Task { try await concurrentEngine.fullSync(accountID: Fixtures.accountID) }
        await concurrentAPI.waitUntilSyncIsPaused()
        for error in [NetworkingError.serverUnreachable, .unauthorized, .http(status: 403, body: "Forbidden")] {
            await api.setSyncError(error)
            do {
                _ = try await engine.fullSync(accountID: Fixtures.accountID)
                runner.expectTrue(false, "failed sync cannot return an authorized Send count")
            } catch let observed as NetworkingError {
                runner.expect(observed, error, "the original sync failure reaches the caller")
            }
            runner.expect(try await store.completeCachedSends(accountID: Fixtures.accountID)?.count, error == .serverUnreachable ? 1 : nil,
                          "transport failure preserves the cache but an explicit denial revokes it")
        }
        await concurrentAPI.resumePausedSync()
        runner.expect(try await delayed.value.sendCount, nil, "a previously in-flight sync cannot publish a revoked count")
        runner.expect(try await store.completeCachedSends(accountID: Fixtures.accountID)?.count, nil, "a previously in-flight sync cannot restore revoked Sends")
        await api.setSyncError(nil)
        await api.setSyncResponse(Fixtures.decodeSync(payload(future + ",{}")))
        runner.expect(try await engine.fullSync(accountID: Fixtures.accountID).sendCount, nil, "an authorized but incomplete sync cannot restore a revoked count")
        runner.expect(try await store.completeCachedSends(accountID: Fixtures.accountID)?.count, nil, "an incomplete sync cannot restore offline access")
        await api.setSyncResponse(Fixtures.decodeSync(payload(future)))
        runner.expect(try await engine.fullSync(accountID: Fixtures.accountID).sendCount, 1, "a newly authorized full sync restores the Send count")
        runner.expect(try await store.completeCachedSends(accountID: Fixtures.accountID)?.count, 1, "a fresh full sync restores the complete offline listing")
    } catch {
        runner.expectTrue(false, "Send sync cache: \(error)")
    }
}
