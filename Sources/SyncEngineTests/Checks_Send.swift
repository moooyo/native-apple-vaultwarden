import Foundation
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
        _ = try await engine.fullSync(accountID: Fixtures.accountID)
        let stored = try await store.cachedSends(accountID: Fixtures.accountID)
        runner.expect(stored.first?.name.stringValue, encryptedName, "Send cache contains original ciphertext")
        runner.expect(try await store.cachedSends(accountID: "other").count, 0, "Send cache is account-scoped")
        let snapshot = await store.sendCacheGeneration(accountID: Fixtures.accountID)
        try await store.evictSend(id: "send-one", accountID: Fixtures.accountID)
        try await store.cacheSends(stored, accountID: Fixtures.accountID, replacing: true, ifUnchangedSince: snapshot)
        runner.expect(try await store.cachedSends(accountID: Fixtures.accountID).count, 0,
                      "sync captured before deletion cannot reinsert a disabled reservation")
        let precedingUpload = await store.sendCacheGeneration(accountID: Fixtures.accountID)
        try await store.cacheSends(stored, accountID: Fixtures.accountID, replacing: false)
        try await store.cacheSends([], accountID: Fixtures.accountID, replacing: true, ifUnchangedSince: precedingUpload)
        runner.expect(try await store.cachedSends(accountID: Fixtures.accountID).count, 1,
                      "stale sync cannot erase the final published upload")
        await api.setSyncResponse(Fixtures.decodeSync(payload("{}")))
        let partial = try await engine.fullSync(accountID: Fixtures.accountID)
        runner.expect(partial.dropped, 1, "malformed Send is reported without aborting vault sync")
        runner.expect(try await store.cachedSends(accountID: Fixtures.accountID).count, 1, "partial Send list retains cached records")
        await api.setSyncResponse(Fixtures.decodeSync(empty))
        _ = try await engine.fullSync(accountID: Fixtures.accountID)
        runner.expect(try await store.cachedSends(accountID: Fixtures.accountID).count, 0, "complete empty Send list clears cache")
    } catch {
        runner.expectTrue(false, "Send sync cache: \(error)")
    }
}
