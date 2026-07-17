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
        try await Fixtures.seedAccounts([Fixtures.accountID], in: store)
        try await store.upsertCiphers([
            CipherRow(
                id: "bad-1", accountID: Fixtures.accountID,
                type: CipherType.login.rawValue,
                revisionDate: Fixtures.iso(base.addingTimeInterval(-60)),
                creationDate: Fixtures.iso(base.addingTimeInterval(-120)),
                encName: Fixtures.enc("Last readable bad item"),
                encBlob: "{}"
            )
        ])
        let outcome = try await engine.fullSync(accountID: Fixtures.accountID)
        r.expectTrue(outcome.dropped > 0, "soft-fail: outcome.dropped > 0")
        r.expect(outcome.upserted, 1, "soft-fail: good cipher still upserted")
        r.expectTrue(!outcome.droppedMessages.isEmpty, "soft-fail: dropped messages surfaced")

        let rows = try await store.allCiphers(accountID: Fixtures.accountID)
        r.expect(rows.count, 2,
                 "soft-fail: malformed omission cannot delete last local cipher copy")
        r.expectTrue(rows.contains { $0.id == "cipher-good" },
                     "soft-fail: good cipher is stored")
        r.expectTrue(rows.contains { $0.id == "bad-1" },
                     "soft-fail: prior copy of dropped cipher is preserved")
    } catch {
        r.expectTrue(false, "soft-fail must NOT throw, but threw: \(error)")
    }
}

func checkWellFormedType7PreservesReadableRow(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "type7 soft-fail: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }
    let base = Date(timeIntervalSince1970: 1_750_000_000)
    let response = Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [
        Fixtures.type7CipherJSON(id: "type7-existing", revision: base)
    ]))
    let engine = SyncEngine(
        api: FakeVaultAPI(syncResponse: response),
        store: store,
        keyVault: await Fixtures.unlockedVault(),
        identityStore: FakeIdentityStore(enabled: false)
    )
    do {
        try await Fixtures.seedAccounts([Fixtures.accountID], in: store)
        try await store.upsertCiphers([
            CipherRow(
                id: "type7-existing", accountID: Fixtures.accountID,
                type: CipherType.login.rawValue,
                revisionDate: Fixtures.iso(base.addingTimeInterval(-60)),
                creationDate: Fixtures.iso(base.addingTimeInterval(-120)),
                encName: Fixtures.enc("Readable old copy"),
                encBlob: "{}", searchText: "readable old copy"
            )
        ])
        let outcome = try await engine.fullSync(accountID: Fixtures.accountID)
        r.expect(outcome.dropped, 1, "type7 soft-fail: unsupported item is reported")
        r.expect((try await store.cipher(
            id: "type7-existing", accountID: Fixtures.accountID
        ))?.searchText, "readable old copy",
                 "type7 soft-fail: last readable row is preserved")
    } catch {
        r.expectTrue(false, "type7 soft-fail threw: \(error)")
    }
}

/// Type 1 is structurally parseable, but the client's symmetric decryptor implements only
/// type 2. It must not replace a previously readable row merely because decoding succeeded.
func checkWellFormedType1PreservesReadableRow(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "type1 soft-fail: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }
    let base = Date(timeIntervalSince1970: 1_750_000_000)
    let response = Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [
        Fixtures.type1CipherJSON(id: "type1-existing", revision: base)
    ]))
    let engine = SyncEngine(
        api: FakeVaultAPI(syncResponse: response),
        store: store,
        keyVault: await Fixtures.unlockedVault(),
        identityStore: FakeIdentityStore(enabled: false)
    )
    do {
        try await Fixtures.seedAccounts([Fixtures.accountID], in: store)
        try await store.upsertCiphers([
            CipherRow(
                id: "type1-existing", accountID: Fixtures.accountID,
                type: CipherType.login.rawValue,
                revisionDate: Fixtures.iso(base.addingTimeInterval(-60)),
                creationDate: Fixtures.iso(base.addingTimeInterval(-120)),
                encName: Fixtures.enc("Readable old copy"),
                encBlob: "{}", searchText: "readable old copy"
            )
        ])
        let outcome = try await engine.fullSync(accountID: Fixtures.accountID)
        r.expect(outcome.dropped, 1,
                 "type1 soft-fail: decryptor-unsupported item is reported")
        r.expect((try await store.cipher(
            id: "type1-existing", accountID: Fixtures.accountID
        ))?.searchText, "readable old copy",
                 "type1 soft-fail: last readable row is preserved")
    } catch {
        r.expectTrue(false, "type1 soft-fail threw: \(error)")
    }
}
