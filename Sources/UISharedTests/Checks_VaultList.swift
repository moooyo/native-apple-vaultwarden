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

    await model.load()

    r.expect(model.items.count, 3, "VaultList: load populates items")
    r.expectFalse(model.isLoading, "VaultList: not loading after load")
    r.expectNil(model.errorMessage, "VaultList: no error after successful load")
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
    await vault.setCiphersError(RepositoryError.locked)
    let model = VaultListModel(vault: vault)

    await model.load()  // must not crash

    r.expectNotNil(model.errorMessage, "VaultList: load error sets errorMessage")
    r.expect(model.items.count, 0, "VaultList: items stay empty on load error")
    r.expectFalse(model.isLoading, "VaultList: isLoading reset on error")
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
}
