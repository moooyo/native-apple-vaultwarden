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
            opType: "create", entityType: "cipher",
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
        let payload = OutboxCipherPayload(type: 1, name: Fixtures.enc("Conflicted"))
        try await store.enqueueOutbox(OutboxRow(
            opType: "create", entityType: "cipher",
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
        // Update op for an existing server id, with a lastKnownRevisionDate.
        let updatePayload = OutboxCipherPayload(type: 1, name: Fixtures.enc("Edited"))
        try await store.enqueueOutbox(OutboxRow(
            opType: "update", entityType: "cipher", entityID: "cipher-1",
            payloadJSON: try updatePayload.encodedJSON(),
            lastKnownRevisionDate: "2026-01-02T03:04:05.123Z"))

        // Delete op.
        try await store.enqueueOutbox(OutboxRow(
            opType: "delete", entityType: "cipher", entityID: "cipher-2",
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
        try await store.enqueueOutbox(OutboxRow(
            opType: "create", entityType: "cipher", entityID: "x",
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
        try await store.enqueueOutbox(OutboxRow(
            opType: "delete", entityType: "cipher", entityID: "gone-1",
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
        let payload = OutboxCipherPayload(type: 1, name: Fixtures.enc("Offline"))
        try await store.enqueueOutbox(OutboxRow(
            opType: "create", entityType: "cipher", entityID: "local-temp-3",
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
        let payload = OutboxCipherPayload(type: 1, name: Fixtures.enc("Edited"))
        try await store.enqueueOutbox(OutboxRow(
            opType: "update", entityType: "cipher", entityID: "cipher-1",
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
