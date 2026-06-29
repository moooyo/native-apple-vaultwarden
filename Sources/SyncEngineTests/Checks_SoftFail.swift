import Foundation
import VaultModels
import VaultStore
import KeyVault
import SyncEngine

/// Soft-fail: a SyncResponse whose `droppedCipherErrors` is non-empty must NOT throw;
/// the good ciphers are still upserted and `SyncOutcome.dropped > 0`.
func checkSoftFailDroppedCiphers(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "soft-fail: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: false)
    let base = Date(timeIntervalSince1970: 1_750_000_000)

    let good = Fixtures.loginCipherJSON(id: "cipher-good", name: "Good", username: "u",
                                        uri: "https://good.test", revision: base)
    // badCipher:true appends a cipher with an invalid EncString name → dropped.
    let response = Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [good], badCipher: true))

    // Sanity: the decoder really did drop the bad cipher.
    r.expect(response.ciphers.count, 1, "decoder kept only the good cipher")
    r.expectTrue(response.droppedCipherErrors.count >= 1, "decoder flagged the bad cipher")

    let api = FakeVaultAPI(syncResponse: response)
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        let outcome = try await engine.fullSync(accountID: Fixtures.accountID)
        r.expectTrue(outcome.dropped > 0, "soft-fail: outcome.dropped > 0")
        r.expect(outcome.upserted, 1, "soft-fail: good cipher still upserted")
        r.expectTrue(!outcome.droppedMessages.isEmpty, "soft-fail: dropped messages surfaced")

        let rows = try await store.allCiphers(accountID: Fixtures.accountID)
        r.expect(rows.count, 1, "soft-fail: store has only the good cipher")
        r.expect(rows.first?.id, "cipher-good", "soft-fail: kept the good cipher")
    } catch {
        r.expectTrue(false, "soft-fail must NOT throw, but threw: \(error)")
    }
}
