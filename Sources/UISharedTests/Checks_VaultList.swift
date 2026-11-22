import Foundation
import VaultModels
import VaultRepository
import SyncEngine
import UIShared

private func sampleCiphers() -> [PlaintextCipher] {
    [
        PlaintextCipher(id: "1", name: "GitHub",
                        login: .init(username: "octocat", password: "p1")),
        PlaintextCipher(id: "2", name: "Gmail",
                        login: .init(username: "alice", password: "p2")),
        PlaintextCipher(id: "3", name: "Bank",
                        login: .init(username: "bob", password: "p3")),
    ]
}

@MainActor
func checkVaultListLoad(_ r: inout TestRunner) async {
    let vault = FakeVaultService(stored: sampleCiphers())
    let model = VaultListModel(vault: vault)
    r.expect(model.items.count, 0, "VaultList: empty before load")
    r.expectFalse(model.canPresentCounts, "VaultList: unknown initial counts are not zero")

    await model.load()

    r.expect(model.items.count, 3, "VaultList: load populates items")
    r.expectFalse(model.isLoading, "VaultList: not loading after load")
    r.expectNil(model.errorMessage, "VaultList: no error after successful load")
    r.expectTrue(model.canPresentCounts, "VaultList: successful reads provide counts")
    model.clearDecryptedItems()
    r.expectFalse(model.hasLoadedContent, "VaultList: clearing secrets discards the snapshot")
}

@MainActor
func checkVaultListSearch(_ r: inout TestRunner) async {
    let vault = FakeVaultService(stored: sampleCiphers())
    let model = VaultListModel(vault: vault)

    await model.search("git")

    r.expect(model.items.count, 1, "VaultList: search filters")
    r.expect(model.items.first?.name, "GitHub", "VaultList: search match correct")
    let queries = await vault.searchQueries
    r.expect(queries, ["git"], "VaultList: query forwarded to service")

    await vault.setSearchError(RepositoryError.locked)
    await model.search("no match")
    r.expectFalse(model.hasLoadedContent, "VaultList: failed searches invalidate previous results")
    r.expectTrue(model.items.isEmpty, "VaultList: failed searches clear previous secrets")
    await vault.setSearchError(nil)
    await model.reloadCurrentView()
    r.expectTrue(model.canPresentCounts && model.items.isEmpty, "VaultList: retry distinguishes genuine zero matches")
    r.expect(model.query, "no match", "VaultList: retry preserves the search query")
}

@MainActor
func checkVaultListSearchEmptyReloads(_ r: inout TestRunner) async {
    let vault = FakeVaultService(stored: sampleCiphers())
    let model = VaultListModel(vault: vault)
    model.query = "   "  // whitespace-only

    await model.search()

    // Empty/whitespace query should reload the full list, not call search.
    r.expect(model.items.count, 3, "VaultList: empty query reloads full list")
    let queries = await vault.searchQueries
    r.expect(queries.count, 0, "VaultList: empty query does not call search()")
}

@MainActor
func checkVaultListRefresh(_ r: inout TestRunner) async {
    let vault = FakeVaultService(
        stored: sampleCiphers(),
        syncOutcome: SyncOutcome(upserted: 2, deletedLocally: 0, dropped: 0,
                                 droppedMessages: [], identitiesWritten: 0))
    let model = VaultListModel(vault: vault)

    await model.refresh()

    let syncCount = await vault.syncCallCount
    let ciphersCount = await vault.ciphersCallCount
    r.expect(syncCount, 1, "VaultList: refresh calls sync")
    r.expect(ciphersCount, 1, "VaultList: refresh reloads ciphers after sync")
    r.expect(model.items.count, 3, "VaultList: refresh repopulates items")
    r.expectNil(model.errorMessage, "VaultList: no error after successful refresh")
}

@MainActor
func checkVaultListLoadError(_ r: inout TestRunner) async {
    let vault = FakeVaultService(stored: sampleCiphers())
    let model = VaultListModel(vault: vault)
    await model.load()
    await vault.setCiphersError(RepositoryError.locked)

    await model.load()  // must not crash

    r.expectNotNil(model.errorMessage, "VaultList: load error sets errorMessage")
    r.expect(model.items.count, 0, "VaultList: items stay empty on load error")
    r.expectFalse(model.isLoading, "VaultList: isLoading reset on error")
    r.expectFalse(model.hasLoadedContent, "VaultList: a failed read invalidates the previous snapshot")
    await vault.setCiphersError(nil)
    await vault.setStored([])
    await model.reloadCurrentView()
    r.expectTrue(model.canPresentCounts && model.items.isEmpty, "VaultList: a successful empty vault has a known count")
}

@MainActor
func checkVaultListRefreshSyncErrorStillReloads(_ r: inout TestRunner) async {
    // Sync fails, but the list should still reload local items (and not crash).
    let vault = FakeVaultService(stored: sampleCiphers())
    await vault.setSyncError(RepositoryError.underlying(kind: .sync, description: "boom"))
    let model = VaultListModel(vault: vault)

    await model.refresh()

    r.expectNotNil(model.errorMessage, "VaultList: refresh sync error sets errorMessage")
    r.expect(model.items.count, 3, "VaultList: refresh still reloads local items on sync error")
    r.expectTrue(model.hasLoadedContent, "VaultList: a failed sync does not discard a successful local read")
    r.expectFalse(model.canPresentCounts, "VaultList: failed sync does not present authoritative counts")
}
