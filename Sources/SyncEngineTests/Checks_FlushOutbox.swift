import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import Networking
import SyncEngine

/// flushOutbox: a queued CREATE op calls the fake API's createCipher and clears the
/// outbox row.
func checkFlushOutboxCreate(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "flush create: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: false)
    // Empty sync response (only used if fullSync is called; here we flush directly).
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [])))
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        try await Fixtures.seedAccounts([Fixtures.accountID], in: store)
        // Enqueue a create op: payload carries a login cipher (EncString wire strings).
        // `Fixtures.enc` is non-deterministic (random IV), so capture the name wire
        // string once for both the payload and the later assertion.
        let nameWire = Fixtures.enc("New Login")
        let payload = OutboxCipherPayload(
            type: 1,
            name: nameWire,
            login: .init(username: Fixtures.enc("alice"),
                         password: Fixtures.enc("hunter2"),
                         uris: [.init(uri: Fixtures.enc("https://new.test"), match: nil)])
        )
        let json = try payload.encodedJSON()
        try await store.enqueueOutbox(OutboxRow(
            accountID: Fixtures.accountID, opType: "create", entityType: "cipher",
            entityID: "local-temp-1", payloadJSON: json, lastKnownRevisionDate: nil))

        r.expect(try await store.outbox().count, 1, "one outbox row queued")

        let outcome = try await engine.flushOutbox(accountID: Fixtures.accountID)
        r.expect(outcome.flushed, 1, "flushOutbox flushed 1 op")
        r.expect(outcome.conflicts, 0, "flushOutbox no conflicts")

        let createdCount = await api.createdRequests.count
        r.expect(createdCount, 1, "API createCipher called once")
        let createdName = await api.createdRequests.first?.name.stringValue
        r.expect(createdName, nameWire, "created request carries the wire name")

        r.expect(try await store.outbox().count, 0, "outbox cleared after successful create")
    } catch {
        r.expectTrue(false, "flush create threw: \(error)")
    }
}

/// `SyncEngine` actors are reentrant while an API request is suspended. Concurrent
/// foreground/background flush calls must coalesce instead of POSTing one create twice.
func checkConcurrentFlushCoalescesCreate(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "concurrent flush: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [])))
    await api.pauseNextCreate()
    let engine = SyncEngine(
        api: api,
        store: store,
        keyVault: await Fixtures.unlockedVault(),
        identityStore: FakeIdentityStore(enabled: false)
    )
    do {
        try await Fixtures.seedAccounts([Fixtures.accountID], in: store)
        let payload = OutboxCipherPayload(type: 1, name: Fixtures.enc("Exactly Once"))
        try await store.enqueueOutbox(OutboxRow(
            accountID: Fixtures.accountID,
            opType: "create",
            entityType: "cipher",
            entityID: "local-concurrent",
            payloadJSON: try payload.encodedJSON()
        ))

        let first = Task { try await engine.flushOutbox(accountID: Fixtures.accountID) }
        await api.waitUntilCreateIsPaused()
        let second = Task { try await engine.flushOutbox(accountID: Fixtures.accountID) }
        // Give the second actor call an opportunity to enter while create is suspended.
        await Task.yield()
        await api.resumePausedCreate()

        r.expect(try await first.value.flushed, 1,
                 "concurrent flush: first caller observes completion")
        r.expect(try await second.value.flushed, 0,
                 "concurrent flush: serialized follower observes an empty queue")
        r.expect(await api.createdRequests.count, 1,
                 "concurrent flush: durable create is POSTed exactly once")
        r.expect(try await store.outbox(accountID: Fixtures.accountID).count, 0,
                 "concurrent flush: row clears once")
    } catch {
        r.expectTrue(false, "concurrent flush threw: \(error)")
    }
}

/// Pre-fix queues may already contain operations after a local-id create. Finalization must
/// preserve the optimistic row, remap later ops to the server id/revision, and reload them.
func checkLegacyCreateSequenceRemapsServerID(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "legacy create sequence: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [])))
    let engine = SyncEngine(
        api: api,
        store: store,
        keyVault: await Fixtures.unlockedVault(),
        identityStore: FakeIdentityStore(enabled: false)
    )
    do {
        try await Fixtures.seedAccounts([Fixtures.accountID], in: store)
        let oldPayload = OutboxCipherPayload(type: 1, name: Fixtures.enc("Old"))
        let latestName = Fixtures.enc("Latest")
        let latestPayload = OutboxCipherPayload(type: 1, name: latestName)
        try await store.enqueueOutbox(OutboxRow(
            accountID: Fixtures.accountID, opType: "create", entityType: "cipher",
            entityID: "legacy-local", payloadJSON: try oldPayload.encodedJSON()
        ))
        try await store.enqueueOutbox(OutboxRow(
            accountID: Fixtures.accountID, opType: "update", entityType: "cipher",
            entityID: "legacy-local", payloadJSON: try latestPayload.encodedJSON(),
            lastKnownRevisionDate: "2026-07-16T00:00:00.000Z"
        ))
        try await store.upsertCiphers([
            CipherRow(
                id: "legacy-local", accountID: Fixtures.accountID, type: 1,
                revisionDate: "2026-07-16T00:00:00.000Z",
                creationDate: "2026-07-16T00:00:00.000Z",
                encName: latestName
            )
        ])

        let outcome = try await engine.flushOutbox(accountID: Fixtures.accountID)
        r.expect(outcome.flushed, 2, "legacy create sequence: create and update flush")
        r.expect(await api.createdRequests.count, 1, "legacy create sequence: one POST")
        r.expect(await api.updatedRequests.first?.id, "server-generated-id",
                 "legacy create sequence: update remapped to server id")
        r.expect(await api.updatedRequests.first?.req.name.stringValue, latestName,
                 "legacy create sequence: latest payload reaches update")
        r.expect(try await store.resolveCipherID(
            "legacy-local", accountID: Fixtures.accountID
        ), "server-generated-id", "legacy create sequence: alias persisted")
        r.expect(try await store.outbox(accountID: Fixtures.accountID).count, 0,
                 "legacy create sequence: queue drains")
    } catch {
        r.expectTrue(false, "legacy create sequence threw: \(error)")
    }
}

func checkLegacyCreateDeleteRemapsServerID(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "legacy create/delete: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [])))
    let engine = SyncEngine(
        api: api, store: store, keyVault: await Fixtures.unlockedVault(),
        identityStore: FakeIdentityStore(enabled: false)
    )
    do {
        try await Fixtures.seedAccounts([Fixtures.accountID], in: store)
        let payload = OutboxCipherPayload(type: 1, name: Fixtures.enc("Delete"))
        try await store.enqueueOutbox(OutboxRow(
            accountID: Fixtures.accountID, opType: "create", entityType: "cipher",
            entityID: "legacy-delete", payloadJSON: try payload.encodedJSON()
        ))
        try await store.enqueueOutbox(OutboxRow(
            accountID: Fixtures.accountID, opType: "delete", entityType: "cipher",
            entityID: "legacy-delete", payloadJSON: "{}"
        ))
        let outcome = try await engine.flushOutbox(accountID: Fixtures.accountID)
        r.expect(outcome.flushed, 2, "legacy create/delete: both operations settle")
        r.expect(await api.deletedIDs, ["server-generated-id"],
                 "legacy create/delete: DELETE targets server id")
        r.expect(try await store.outbox(accountID: Fixtures.accountID).count, 0,
                 "legacy create/delete: queue drains")
    } catch {
        r.expectTrue(false, "legacy create/delete threw: \(error)")
    }
}

/// A pre-fix crash could leave a receipt linked to an outbox row but not yet completed.
/// If SyncEngine sent that create and then deleted the outbox, `ON DELETE SET NULL`
/// erased the link and a drainer replay enqueued a second create. Successful response
/// reconciliation must now complete the receipt and replace the placeholder atomically;
/// even a drainer that made its initial decision from stale state cannot resurrect it.
func checkPasskeyReceiptFinalizationPreventsReplay(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "passkey receipt finalization: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [])))
    let engine = SyncEngine(
        api: api,
        store: store,
        keyVault: keyVault,
        identityStore: FakeIdentityStore(enabled: false)
    )
    let accountID = Fixtures.accountID
    let receiptID = "receipt-before-local-commit"
    let localID = "passkey-\(receiptID)"
    let nameWire = Fixtures.enc("Pending Passkey")
    let payload = OutboxCipherPayload(type: 1, name: nameWire)
    let operation: OutboxRow
    do {
        operation = OutboxRow(
            accountID: accountID,
            opType: "create",
            entityType: "cipher",
            entityID: localID,
            payloadJSON: try payload.encodedJSON()
        )
    } catch {
        r.expectTrue(false, "passkey receipt finalization: encode payload: \(error)")
        return
    }
    let placeholder = CipherRow(
        id: localID,
        accountID: accountID,
        type: 1,
        revisionDate: "2026-07-16T00:00:00.000Z",
        creationDate: "2026-07-16T00:00:00.000Z",
        encName: nameWire
    )

    do {
        try await Fixtures.seedAccounts([accountID], in: store)
        // Reconstruct the old two-phase crash state: receipt/outbox committed, while
        // local-row upsert + receipt completion have not happened yet.
        r.expectTrue(try await store.enqueueOutboxForPasskeyImport(
            receiptID: receiptID,
            accountID: accountID,
            operation: operation
        ), "passkey receipt finalization: pending receipt created")
        r.expectTrue(!(try await store.isPasskeyImportCompleted(
            id: receiptID,
            accountID: accountID
        )), "passkey receipt finalization: reconstructed receipt is pending")

        let outcome = try await engine.flushOutbox(accountID: accountID)
        r.expect(outcome.flushed, 1, "passkey receipt finalization: create flushed")
        r.expect(await api.createdRequests.count, 1,
                 "passkey receipt finalization: online create called once")
        r.expectTrue(try await store.isPasskeyImportCompleted(
            id: receiptID,
            accountID: accountID
        ), "passkey receipt finalization: send completes durable receipt")
        r.expectTrue(try await store.cipher(id: localID, accountID: Fixtures.accountID) == nil,
                     "passkey receipt finalization: placeholder removed")
        r.expect((try await store.cipher(
            id: "server-generated-id",
            accountID: Fixtures.accountID
        ))?.encName, nameWire,
                 "passkey receipt finalization: server-id row persisted")
        r.expect(try await store.outbox(accountID: accountID).count, 0,
                 "passkey receipt finalization: linked outbox cleared")

        // Model the drainer resuming with a stale preflight result after SyncEngine's
        // transaction. Its final persistence attempt must be a no-op.
        r.expectTrue(!(try await store.enqueueOutboxForPasskeyImport(
            receiptID: receiptID,
            accountID: accountID,
            operation: operation,
            localCipher: placeholder
        )), "passkey receipt finalization: stale drainer commit is rejected")
        r.expectTrue(try await store.cipher(id: localID, accountID: Fixtures.accountID) == nil,
                     "passkey receipt finalization: stale replay cannot resurrect placeholder")
        r.expect(try await store.outbox(accountID: accountID).count, 0,
                 "passkey receipt finalization: stale replay cannot enqueue create")

        _ = try await engine.flushOutbox(accountID: accountID)
        r.expect(await api.createdRequests.count, 1,
                 "passkey receipt finalization: later flush does not create again")
    } catch {
        r.expectTrue(false, "passkey receipt finalization threw: \(error)")
    }
}

/// flushOutbox conflict: a fake API that throws an HTTP 400 conflict leaves the outbox
/// row in place and records a conflict (does not crash, does not clear).
func checkFlushOutboxConflict(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "flush conflict: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: false)
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [])))
    // Server has a newer revision → 400 stale on create.
    await api.setCreateError(NetworkingError.http(status: 400, body: "stale"))
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        try await Fixtures.seedAccounts([Fixtures.accountID], in: store)
        let payload = OutboxCipherPayload(type: 1, name: Fixtures.enc("Conflicted"))
        try await store.enqueueOutbox(OutboxRow(
            accountID: Fixtures.accountID, opType: "create", entityType: "cipher",
            entityID: "local-temp-2", payloadJSON: try payload.encodedJSON()))

        let outcome = try await engine.flushOutbox(accountID: Fixtures.accountID)
        r.expect(outcome.flushed, 0, "conflict: nothing flushed")
        r.expect(outcome.conflicts, 1, "conflict: one conflict recorded")
        r.expect(try await store.outbox().count, 1, "conflict: outbox row REMAINS")
    } catch {
        r.expectTrue(false, "flush conflict should not throw, but threw: \(error)")
    }
}

/// flushOutbox update + delete ops route to the right API calls and clear.
func checkFlushOutboxUpdateAndDelete(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "flush update/delete: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: false)
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [])))
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        try await Fixtures.seedAccounts([Fixtures.accountID], in: store)
        // Update op for an existing server id, with a lastKnownRevisionDate.
        let updatePayload = OutboxCipherPayload(type: 1, name: Fixtures.enc("Edited"))
        try await store.enqueueOutbox(OutboxRow(
            accountID: Fixtures.accountID, opType: "update",
            entityType: "cipher", entityID: "cipher-1",
            payloadJSON: try updatePayload.encodedJSON(),
            lastKnownRevisionDate: "2026-01-02T03:04:05.123Z"))

        // Delete op.
        try await store.enqueueOutbox(OutboxRow(
            accountID: Fixtures.accountID, opType: "delete",
            entityType: "cipher", entityID: "cipher-2",
            payloadJSON: "{}"))

        let outcome = try await engine.flushOutbox(accountID: Fixtures.accountID)
        r.expect(outcome.flushed, 2, "flushed both update + delete")

        let updated = await api.updatedRequests
        r.expect(updated.count, 1, "updateCipher called once")
        r.expect(updated.first?.id, "cipher-1", "update targets cipher-1")
        r.expectTrue(updated.first?.req.lastKnownRevisionDate != nil,
                     "update carries lastKnownRevisionDate for optimistic concurrency")

        let deleted = await api.deletedIDs
        r.expect(deleted, ["cipher-2"], "deleteCipher called with cipher-2")

        r.expect(try await store.outbox().count, 0, "outbox cleared after update+delete")
    } catch {
        r.expectTrue(false, "flush update/delete threw: \(error)")
    }
}

/// flushOutbox on a malformed payload throws a SyncError (hard error — a corrupt row
/// can never succeed).
func checkFlushOutboxMalformedPayload(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "flush malformed: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: false)
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [])))
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        try await Fixtures.seedAccounts([Fixtures.accountID], in: store)
        try await store.enqueueOutbox(OutboxRow(
            accountID: Fixtures.accountID, opType: "create",
            entityType: "cipher", entityID: "x",
            payloadJSON: "{ this is not valid json"))
    } catch {
        r.expectTrue(false, "enqueue malformed setup threw: \(error)"); return
    }

    await r.expectThrowsAsync("flush malformed payload throws") {
        _ = try await engine.flushOutbox(accountID: Fixtures.accountID)
    }
}

/// flushOutbox delete-already-deleted: a DELETE op whose API throws HTTP 404 means the
/// server already removed the cipher → the row must be CLEARED (the desired end state),
/// not left to re-404 forever.
func checkFlushOutboxDelete404Clears(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "flush delete-404: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: false)
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [])))
    await api.setDeleteError(NetworkingError.http(status: 404, body: "not found"))
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        try await Fixtures.seedAccounts([Fixtures.accountID], in: store)
        try await store.enqueueOutbox(OutboxRow(
            accountID: Fixtures.accountID, opType: "delete",
            entityType: "cipher", entityID: "gone-1",
            payloadJSON: "{}"))

        let outcome = try await engine.flushOutbox(accountID: Fixtures.accountID)
        r.expect(outcome.flushed, 1, "delete-404 counts as flushed (desired end state)")
        r.expect(outcome.conflicts, 0, "delete-404 is NOT a conflict")
        r.expect(try await store.outbox().count, 0, "delete-404 CLEARS the outbox row")
    } catch {
        r.expectTrue(false, "flush delete-404 should not throw, but threw: \(error)")
    }
}

/// flushOutbox transport failure: a transport / serverUnreachable error must LEAVE the
/// row queued (so a later retry can flush it) AND surface by throwing.
func checkFlushOutboxTransportLeavesQueued(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "flush transport: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: false)
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [])))
    await api.setCreateError(NetworkingError.serverUnreachable)
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        try await Fixtures.seedAccounts([Fixtures.accountID], in: store)
        let payload = OutboxCipherPayload(type: 1, name: Fixtures.enc("Offline"))
        try await store.enqueueOutbox(OutboxRow(
            accountID: Fixtures.accountID, opType: "create",
            entityType: "cipher", entityID: "local-temp-3",
            payloadJSON: try payload.encodedJSON()))
    } catch {
        r.expectTrue(false, "flush transport setup threw: \(error)"); return
    }

    await r.expectThrowsAsync("transport error during flush throws") {
        _ = try await engine.flushOutbox(accountID: Fixtures.accountID)
    }
    // The row must survive for a later retry (clearOutbox was NOT called).
    let remaining = (try? await store.outbox().count) ?? -1
    r.expect(remaining, 1, "transport error LEAVES the outbox row queued")
}

/// flushOutbox corrupt concurrency token: an UPDATE op with a non-nil but unparseable
/// `lastKnownRevisionDate` must NOT silently send an unguarded update. It's left queued
/// and counted as a conflict.
func checkFlushOutboxCorruptToken(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "flush corrupt-token: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: false)
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [])))
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        try await Fixtures.seedAccounts([Fixtures.accountID], in: store)
        let payload = OutboxCipherPayload(type: 1, name: Fixtures.enc("Edited"))
        try await store.enqueueOutbox(OutboxRow(
            accountID: Fixtures.accountID, opType: "update",
            entityType: "cipher", entityID: "cipher-1",
            payloadJSON: try payload.encodedJSON(),
            lastKnownRevisionDate: "not-a-real-date"))

        let outcome = try await engine.flushOutbox(accountID: Fixtures.accountID)
        r.expect(outcome.flushed, 0, "corrupt token: nothing flushed")
        r.expect(outcome.conflicts, 1, "corrupt token: counted as a conflict")

        let updatedCount = await api.updatedRequests.count
        r.expect(updatedCount, 0, "corrupt token: updateCipher NOT called (no unguarded write)")
        r.expect(try await store.outbox().count, 1, "corrupt token: outbox row REMAINS")
    } catch {
        r.expectTrue(false, "flush corrupt-token should not throw, but threw: \(error)")
    }
}

/// A flush authenticated as account A must never decode, send, or clear account B's
/// queued writes. B deliberately carries malformed JSON so any accidental cross-account
/// read turns into a hard failure instead of passing unnoticed.
func checkFlushOutboxAccountIsolation(_ r: inout TestRunner) async {
    guard let (store, dir) = try? Fixtures.freshStore() else {
        r.expectTrue(false, "flush account isolation: fresh store"); return
    }
    defer { Fixtures.cleanup(dir) }

    let accountA = Fixtures.accountID
    let accountB = "user-2"
    let keyVault = await Fixtures.unlockedVault()
    let identity = FakeIdentityStore(enabled: false)
    let api = FakeVaultAPI(syncResponse: Fixtures.decodeSync(Fixtures.syncJSON(ciphers: [])))
    let engine = SyncEngine(api: api, store: store, keyVault: keyVault, identityStore: identity)

    do {
        try await Fixtures.seedAccounts([accountA, accountB], in: store)
        let accountAName = Fixtures.enc("Account A only")
        let accountAPayload = OutboxCipherPayload(type: 1, name: accountAName)
        try await store.enqueueOutbox(OutboxRow(
            accountID: accountA, opType: "create", entityType: "cipher",
            entityID: "local-a", payloadJSON: try accountAPayload.encodedJSON()))
        try await store.enqueueOutbox(OutboxRow(
            accountID: accountB, opType: "create", entityType: "cipher",
            entityID: "local-b", payloadJSON: "{ malformed account-b payload"))

        let outcome = try await engine.flushOutbox(accountID: accountA)
        r.expect(outcome.flushed, 1, "account A flush sends only A row")
        r.expect(outcome.conflicts, 0, "account A flush has no conflicts")
        r.expect(await api.createdRequests.count, 1, "account B API request is never sent")
        r.expect(await api.createdRequests.first?.name.stringValue, accountAName,
                 "only account A payload reaches API")
        r.expect(try await store.outbox(accountID: accountA).count, 0,
                 "account A row cleared")
        let remainingB = try await store.outbox(accountID: accountB)
        r.expect(remainingB.count, 1, "account B row remains queued")
        r.expect(remainingB.first?.entityID, "local-b", "account B row is untouched")
    } catch {
        r.expectTrue(false, "flush account isolation threw: \(error)")
    }
}
