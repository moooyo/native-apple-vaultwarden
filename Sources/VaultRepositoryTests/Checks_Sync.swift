import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import KeychainBridge
import Networking
import SyncEngine
import VaultRepository
import AppShared

func checkScopedSyncDenials(_ runner: inout TestRunner) async {
    guard let (harness, account) = await loggedInHarness(&runner) else { return }
    defer { Fixtures.cleanup(harness.dir) }
    guard let session = await harness.auth.currentSessionLease() else { runner.expectTrue(false, "missing sync session"); return }
    for denial in [NetworkingError.unauthorized, .http(status: 403, body: "Forbidden")] {
        await harness.api.setSyncError(denial)
        await runner.expectThrowsErrorAsync(RepositoryError.vaultAccessDenied, "full vault denial stays typed at the repository boundary") {
            _ = try await harness.vault.sync(expectedSession: session)
        }
    }
    let before = await harness.api.syncCallCount
    await runner.expectThrowsErrorAsync(RepositoryError.notAuthenticated, "a sync cannot run for a replaced session") {
        _ = try await harness.vault.sync(expectedSession: .init(accountID: account, generation: session.generation &+ 1))
    }
    runner.expect(await harness.api.syncCallCount, before, "a mismatched session never starts a server request")
}

func checkOutboxConflictUsesLatestServerVersion(_ runner: inout TestRunner) async {
    let cipherID = "concurrent-edit"
    let revision = Date(timeIntervalSince1970: 1_700_000_000)
    do {
        let original = try conflictCipher(id: cipherID, name: "Original", revision: revision)
        let server = ConflictTestServer(cipher: original)
        guard let (harness, accountID) = await loggedInHarness(&runner, cipherServer: server) else { return }
        defer { Fixtures.cleanup(harness.dir) }
        guard let (peer, _) = await loggedInHarness(&runner, cipherServer: server) else { return }
        defer { Fixtures.cleanup(peer.dir) }
        try await harness.vault.sync()
        try await peer.vault.sync()
        var local = try await harness.vault.cipher(id: cipherID)
        var remote = try await peer.vault.cipher(id: cipherID)
        local.name = "Local offline edit"
        await harness.api.setUpdateError(NetworkingError.serverUnreachable)
        try await harness.vault.updateCipher(id: cipherID, local)
        let pending = try await harness.vault.outboxStatus()
        runner.expect(pending.pendingCount, 1, "outbox: offline edit is pending")
        runner.expectTrue(pending.issues.isEmpty, "outbox: reachability alone is not a conflict")

        remote.name = "Other client edit"
        try await peer.vault.updateCipher(id: cipherID, remote)
        await harness.api.setUpdateError(nil)
        try await harness.vault.sync()
        let status = try await harness.vault.outboxStatus()
        guard status.issues.count == 1, let issue = status.issues.first else {
            runner.expectTrue(false, "outbox: successful pull exposes exactly one conflict"); return
        }
        runner.expect(issue.kind, .updateConflict, "outbox: identifies the conflicting edit")
        runner.expect(issue.itemName, "Local offline edit", "outbox: conflict is named with the preserved local item")
        runner.expectTrue(issue.canKeepLocalCopy, "outbox: conflict permits a non-overwriting copy")
        runner.expect(try await harness.vault.cipher(id: cipherID).name, "Local offline edit",
                      "outbox: pull leaves the local edit intact")

        let writesBefore = await harness.api.updatedRequests.count
        local = try await harness.vault.cipher(id: cipherID)
        local.name = "Blocked attempt to edit a conflicted item"
        await runner.expectThrowsAsync("outbox: an unresolved conflict cannot be edited before resolution") {
            try await harness.vault.updateCipher(id: cipherID, local)
        }
        try await harness.vault.sync()
        runner.expect(await harness.api.updatedRequests.count, writesBefore,
                      "outbox: later sync does not silently retry a parked conflict")
        runner.expect(try await harness.vault.outboxStatus().issues.first?.id, issue.id,
                      "outbox: parked conflict remains identifiable")

        guard let lease = await harness.auth.currentSessionLease() else {
            runner.expectTrue(false, "outbox: missing session"); return
        }
        let staleLease = AccountSessionLease(accountID: accountID, generation: lease.generation &+ 1)
        let readsBefore = await harness.api.syncCallCount
        await runner.expectThrowsErrorAsync(RepositoryError.notAuthenticated,
                                            "outbox: a stale account cannot resolve an issue") {
            try await harness.vault.resolveOutboxIssue(issue, action: .useServer, expectedSession: staleLease)
        }
        runner.expect(await harness.api.syncCallCount, readsBefore, "outbox: wrong session never fetches the server copy")
        try await harness.store.setOutboxIssue(id: issue.id, accountID: accountID, issue: .deleteConflict)
        await runner.expectThrowsErrorAsync(RepositoryError.outboxIssueChanged, "outbox: issue kind changed since confirmation") {
            try await harness.vault.resolveOutboxIssue(issue, action: .useServer, expectedSession: lease)
        }
        try await harness.store.setOutboxIssue(id: issue.id, accountID: accountID, issue: .updateConflict)
        guard let optimistic = try await harness.store.cipher(id: cipherID, accountID: accountID),
              let parked = try await harness.store.outbox(accountID: accountID).first else {
            runner.expectTrue(false, "outbox: optimistic state is available for stale confirmation checks"); return
        }
        try await harness.store.upsertCiphers([
            CipherRow(id: optimistic.id, accountID: accountID, type: optimistic.type,
                      revisionDate: "2090-01-01T00:00:00.000Z", creationDate: optimistic.creationDate,
                      encName: optimistic.encName, encNotes: optimistic.encNotes, encBlob: optimistic.encBlob,
                      encCipherKey: optimistic.encCipherKey)
        ])
        await runner.expectThrowsErrorAsync(RepositoryError.outboxIssueChanged, "outbox: local revision changed since confirmation") {
            try await harness.vault.resolveOutboxIssue(issue, action: .useServer, expectedSession: lease)
        }
        guard let beforeRemoval = try await harness.vault.outboxStatus().issues.first else {
            runner.expectTrue(false, "outbox: changed revision is reflected in new issue snapshot"); return
        }
        try await harness.store.clearOutbox(id: issue.id, accountID: accountID)
        let replacementID = try await harness.store.enqueueOutbox(.init(accountID: accountID, opType: parked.opType,
            entityType: parked.entityType, entityID: cipherID, payloadJSON: parked.payloadJSON,
            lastKnownRevisionDate: parked.lastKnownRevisionDate, issue: parked.issue))
        await runner.expectThrowsErrorAsync(RepositoryError.outboxIssueChanged, "outbox: row identity changed since confirmation") {
            try await harness.vault.resolveOutboxIssue(beforeRemoval, action: .useServer, expectedSession: lease)
        }
        runner.expect(await harness.api.syncCallCount, readsBefore, "outbox: stale confirmation never fetches or modifies server state")
        guard let refreshedIssue = try await harness.vault.outboxStatus().issues.first,
              refreshedIssue.id == replacementID else {
            runner.expectTrue(false, "outbox: replacement issue is identifiable"); return
        }

        let sendGeneration = try await harness.store.sendCacheGeneration(accountID: accountID)
        await harness.api.setSyncError(.http(status: 403, body: "Forbidden"))
        await runner.expectThrowsErrorAsync(RepositoryError.vaultAccessDenied, "outbox: server denial remains typed") {
            try await harness.vault.resolveOutboxIssue(refreshedIssue, action: .useServer, expectedSession: lease)
        }
        runner.expectTrue(try await harness.store.sendCacheGeneration(accountID: accountID) != sendGeneration,
                          "outbox: authoritative listing denial revokes the cached Send snapshot")
        await harness.api.setSyncError(nil)
        await harness.api.setSyncResponse(try Fixtures.syncResponse(ciphers: [], malformedCipher: true))
        await runner.expectThrowsAsync("outbox: a partial listing cannot prove the missing original was deleted") {
            try await harness.vault.resolveOutboxIssue(refreshedIssue, action: .useServer, expectedSession: lease)
        }
        runner.expect(try await harness.vault.cipher(id: cipherID).name, "Local offline edit",
                      "outbox: failed reconciliation preserves the local edit")
        runner.expect(try await harness.vault.outboxStatus().issues.first?.id, refreshedIssue.id,
                      "outbox: failed reconciliation keeps the conflict")

        await harness.api.setSyncResponse(nil)
        remote = try await peer.vault.cipher(id: cipherID)
        remote.name = "Newest server version"
        try await peer.vault.updateCipher(id: cipherID, remote)
        let latest = try await peer.vault.cipher(id: cipherID)
        try await harness.vault.resolveOutboxIssue(refreshedIssue, action: .useServer, expectedSession: lease)
        let resolved = try await harness.vault.cipher(id: cipherID)
        runner.expect(resolved.name, "Newest server version", "outbox: replaces the local snapshot with the fresh server version")
        runner.expect(resolved.revisionDate, latest.revisionDate, "outbox: adopts the server clock over the optimistic local clock")
        runner.expect(try await harness.store.outbox(accountID: accountID).count, 0, "outbox: server choice removes queued edit")
        runner.expect(await harness.api.updatedRequests.count, writesBefore, "outbox: server choice sends no update")
    } catch { runner.expectTrue(false, "outbox server-version regression threw: \(error)") }
}

func checkOutboxConflictKeepsIndependentCopy(_ runner: inout TestRunner) async {
    guard let (harness, accountID) = await loggedInHarness(&runner) else { return }
    defer { Fixtures.cleanup(harness.dir) }
    let cipherID = "copy-conflict"
    let revision = Date(timeIntervalSince1970: 1_700_000_000)
    do {
        let relyingParty = "local.example.test"
        let sharedCredential = PlaintextCipher.Fido2Credential(
            credentialId: "3a461e2d-0059-4cf1-9101-ad5de2cad2b1",
            keyValue: "shared-key-fixture", rpId: relyingParty, userHandle: "shared-user-fixture", creationDate: revision)
        let uniqueCredential = PlaintextCipher.Fido2Credential(
            credentialId: "3a461e2d-0059-4cf1-9101-ad5de2cad2b2",
            keyValue: "local-key-fixture", rpId: relyingParty, userHandle: "local-user-fixture", creationDate: revision)
        let original = try conflictCipher(id: cipherID, name: "Original", revision: revision,
                                          key: Fixtures.protectedCipherKey())
        await harness.api.setSyncResponse(try Fixtures.syncResponse(ciphers: [original]))
        try await harness.vault.sync()
        var local = try await harness.vault.cipher(id: cipherID)
        local.name = "Independent local item"
        local.notes = "Keep these offline notes"
        local.login = .init(username: "local-user", uris: [.init(uri: "https://local.example.test")],
                            fido2Credentials: [sharedCredential, uniqueCredential])
        await harness.api.setUpdateError(NetworkingError.serverUnreachable)
        try await harness.vault.updateCipher(id: cipherID, local)

        var serverCredential = sharedCredential
        serverCredential.credentialId = sharedCredential.credentialId?.uppercased()
        let remoteCredential = try CipherFido2CredentialRequest(
            credentialId: serverCredential.credentialId.map { try EncString(parsing: Fixtures.enc($0)) },
            keyValue: serverCredential.keyValue.map { try EncString(parsing: Fixtures.enc($0)) },
            rpId: serverCredential.rpId.map { try EncString(parsing: Fixtures.enc($0)) },
            userHandle: serverCredential.userHandle.map { try EncString(parsing: Fixtures.enc($0)) }, creationDate: revision)
        let serverRequest = CipherRequest(type: CipherType.login.rawValue,
            name: try EncString(parsing: Fixtures.enc("Server item")), login: .init(fido2Credentials: [remoteCredential]))
        let concurrent = FakeAPI.echo(serverRequest, id: cipherID, revision: revision.addingTimeInterval(60), creation: revision)
        await harness.api.setSyncResponse(try Fixtures.syncResponse(ciphers: [concurrent]))
        await harness.api.setUpdateError(NetworkingError.http(status: 409, body: "Conflict"))
        try await harness.vault.sync()
        guard let issue = try await harness.vault.outboxStatus().issues.first else {
            runner.expectTrue(false, "outbox copy: missing update conflict"); return
        }
        try await harness.vault.resolveOutboxIssue(issue, action: .keepLocalCopy)
        let queue = try await harness.store.outbox(accountID: accountID)
        guard queue.count == 1, let copy = queue.first, copy.entityID != cipherID else {
            runner.expectTrue(false, "outbox copy: only an independent local item is queued"); return
        }
        runner.expect(copy.opType, OutboxOp.create.rawValue, "outbox copy: only a fresh create can be replayed")
        let localCopy = try await harness.vault.cipher(id: copy.entityID)
        var expectedLogin = local.login
        expectedLogin?.fido2Credentials = [uniqueCredential]
        runner.expect(localCopy.notes, local.notes, "outbox copy: retained encrypted notes are readable")
        runner.expect(localCopy.login, expectedLogin, "outbox copy: login retains unique local credential without cloning shared one")
        let remote = try await harness.vault.cipher(id: cipherID)
        runner.expect(remote.name, "Server item", "outbox copy: server version owns the original id")
        runner.expect(remote.login?.fido2Credentials, [serverCredential], "outbox copy: shared credential remains on original item")

        let updatesBefore = await harness.api.updatedRequests.count
        let payload = try OutboxCipherPayload.decode(copy.payloadJSON)
        let expectedRequest = try payload.cipherRequest(lastKnownRevisionDate: nil)
        let serverCopy = FakeAPI.echo(expectedRequest, id: "server-id-1")
        await harness.api.setSyncResponse(try Fixtures.syncResponse(ciphers: [concurrent, serverCopy]))
        try await harness.vault.sync()
        runner.expect(await harness.api.createdRequests.count, 1, "outbox copy: one independent create is uploaded")
        runner.expect(await harness.api.updatedRequests.count, updatesBefore, "outbox copy: original is never pushed again")
        let savedCopy = try await harness.vault.cipher(id: serverCopy.id)
        runner.expect(savedCopy.login, expectedLogin, "outbox copy: uploaded login and unique credential remain readable")
        runner.expect(savedCopy.notes, local.notes, "outbox copy: uploaded notes remain readable")
        let cleared = try await harness.vault.outboxStatus()
        runner.expect(cleared.pendingCount, 0, "outbox copy: successful upload clears pending status")
        runner.expectTrue(cleared.issues.isEmpty, "outbox copy: resolved conflict no longer appears")
    } catch { runner.expectTrue(false, "outbox copy regression threw: \(error)") }
}

func checkOutboxCanAbandonBlockedOperations(_ runner: inout TestRunner) async {
    guard let (harness, _) = await loggedInHarness(&runner) else { return }
    defer { Fixtures.cleanup(harness.dir) }
    let revision = Date(timeIntervalSince1970: 1_700_000_000)
    do {
        await harness.api.setCreateError(NetworkingError.unauthorized)
        await runner.expectThrowsAsync("outbox: direct authorization failure is not reported as a successful create") {
            _ = try await harness.vault.createCipher(.init(name: "Unauthorized operation"))
        }
        runner.expect(try await harness.vault.outboxStatus().pendingCount, 0,
                      "outbox: retrying an editor failure cannot duplicate a pending create")
        runner.expect(try await harness.vault.ciphers().count, 0, "outbox: a denied direct create leaves no optimistic row")

        let trashed = try conflictCipher(id: "deletion-conflict", name: "Still in server trash",
                                        revision: revision, deleted: revision)
        await harness.api.setSyncResponse(try Fixtures.syncResponse(ciphers: [trashed]))
        try await harness.vault.sync()
        await harness.api.setDeleteError(NetworkingError.serverUnreachable)
        await harness.api.setCreateError(NetworkingError.serverUnreachable)
        try await harness.vault.permanentlyDeleteCipher(id: trashed.id)
        let rejectedID = try await harness.vault.createCipher(.init(name: "Create rejected on replay"))

        await harness.api.setDeleteError(NetworkingError.http(status: 409, body: "Conflict"))
        await harness.api.setCreateError(NetworkingError.unauthorized)
        await runner.expectThrowsAsync("outbox: queued authorization failure stops the upload cycle") {
            _ = try await harness.vault.sync()
        }
        runner.expect(try await harness.vault.outboxStatus().pendingCount, 1,
                      "outbox: an already saved create stays retryable after authorization failure")

        await harness.api.setCreateError(NetworkingError.http(status: 422, body: "Validation failed"))
        try await harness.vault.sync()
        let blocked = try await harness.vault.outboxStatus()
        guard blocked.issues.count == 2,
              let deletion = blocked.issues.first(where: { $0.kind == .deleteConflict }),
              let creation = blocked.issues.first(where: { $0.kind == .rejectedCreate }) else {
            runner.expectTrue(false, "outbox: rejected create and delete appear as distinct issues"); return
        }
        runner.expectTrue(!deletion.canKeepLocalCopy, "outbox: an optimistic deletion has nothing to copy")
        runner.expect(deletion.itemName, "Still in server trash", "outbox: deleted items retain an encrypted name preview")
        await runner.expectThrowsAsync("outbox: deleting issue cannot be resolved by copying") {
            try await harness.vault.resolveOutboxIssue(deletion, action: .keepLocalCopy)
        }
        let deletes = await harness.api.deletedIDs.count
        let creates = await harness.api.createdRequests.count
        try await harness.vault.resolveOutboxIssue(deletion, action: .useServer)
        runner.expect(try await harness.vault.trashedCiphers().map(\.id), [trashed.id],
                      "outbox: canceling an optimistic deletion restores the server trash row")
        runner.expect(try await harness.vault.outboxStatus().issues.map(\.id), [creation.id],
                      "outbox: resolving one issue leaves unrelated work parked")
        try await harness.vault.resolveOutboxIssue(creation, action: .useServer)
        await runner.expectThrowsErrorAsync(RepositoryError.cipherNotFound, "outbox: abandoning a rejected item removes its local row") {
            _ = try await harness.vault.cipher(id: rejectedID)
        }
        runner.expect(try await harness.vault.outboxStatus().issues.count, 0, "outbox: both resolved issues disappear")
        runner.expect(await harness.api.createdRequests.count, creates, "outbox: abandoning a create makes no new POST")
        runner.expect(await harness.api.deletedIDs.count, deletes, "outbox: abandoning a delete makes no new DELETE")
    } catch { runner.expectTrue(false, "outbox rejected operations regression threw: \(error)") }
}

func checkAmbiguousCreateDoesNotResend(_ runner: inout TestRunner) async {
    await checkAmbiguousCreateDoesNotResend(&runner, queuedReplay: false)
    await checkAmbiguousCreateDoesNotResend(&runner, queuedReplay: true)
}

private func checkAmbiguousCreateDoesNotResend(_ runner: inout TestRunner, queuedReplay: Bool) async {
    guard let (harness, accountID) = await loggedInHarness(&runner) else { return }
    defer { Fixtures.cleanup(harness.dir) }
    do {
        let local = PlaintextCipher(type: CipherType.login.rawValue, name: "Lost create reply",
                                    protectedCipherKey: Fixtures.protectedCipherKey(), login: .init(username: "local-user"))
        let initialFailure: NetworkingError = queuedReplay ? .serverUnreachable : .cipherCreateUnconfirmed
        await harness.api.setCreateError(initialFailure)
        let localID = try await harness.vault.createCipher(local)
        let expectedAttempts = queuedReplay ? 2 : 1
        if queuedReplay {
            let pending = try await harness.vault.outboxStatus()
            runner.expect(pending.pendingCount, 1, "ambiguous create: definite initial reachability error leaves a retryable create")
            runner.expectTrue(pending.issues.isEmpty, "ambiguous create: an unsent create is not unconfirmed")
            await harness.api.setCreateError(NetworkingError.transport("Fixture lost the create reply"))
            await harness.api.setSyncResponse(try Fixtures.syncResponse(ciphers: []))
            try await harness.vault.sync()
        }
        let requests = await harness.api.createdRequests
        guard requests.count == expectedAttempts, let request = requests.last, let wrappedKey = request.key else {
            runner.expectTrue(false, "ambiguous create: expected attempts retained the item key"); return
        }
        let accepted = FakeAPI.echo(request, id: "committed-server-id")
        let cipherKey = try await harness.keyVault.cipherKey(fromProtected: wrappedKey)
        var unrelatedRequest = request
        unrelatedRequest.login?.username = try SymmetricCrypto.encrypt(Data("other user".utf8), using: cipherKey)
        let unrelated = FakeAPI.echo(unrelatedRequest, id: "unrelated-item")
        await harness.api.setCreateError(nil)
        await harness.api.setSyncResponse(try Fixtures.syncResponse(ciphers: [unrelated]))
        try await harness.vault.sync()
        let uncertain = try await harness.vault.outboxStatus()
        runner.expect(uncertain.issues.first?.kind, .unconfirmedCreate,
                      "ambiguous create: matching encrypted name and key without the other encrypted fields is insufficient")
        runner.expect(await harness.api.createdRequests.count, expectedAttempts,
                      "ambiguous create: a pull with no match does not repeat POST")
        runner.expect(try await harness.vault.cipher(id: localID).login?.username, "local-user",
                      "ambiguous create: the unconfirmed local item remains accessible")

        await harness.api.setSyncResponse(try Fixtures.syncResponse(ciphers: [accepted], malformedCipher: true))
        try await harness.vault.sync()
        runner.expect(try await harness.vault.outboxStatus().issues.first?.kind, .unconfirmedCreate,
                      "ambiguous create: a lossy listing cannot prove a unique match")

        await harness.api.setSyncResponse(try Fixtures.syncResponse(ciphers: [unrelated, accepted]))
        try await harness.vault.sync()
        runner.expect(try await harness.vault.outboxStatus().issues.first?.kind, .unconfirmedCreate,
                      "ambiguous create: repeating the encrypted item identity cannot prove a unique delivery")

        await harness.api.setSyncResponse(try Fixtures.syncResponse(ciphers: [accepted]))
        try await harness.vault.sync()
        runner.expect(await harness.api.createdRequests.count, expectedAttempts,
                      "ambiguous create: recovering the response issues no extra POST")
        runner.expect(try await harness.store.resolveCipherID(localID, accountID: accountID), accepted.id,
                      "ambiguous create: exact encrypted match replaces the optimistic id")
        runner.expect(try await harness.vault.cipher(id: accepted.id).login?.username, "local-user",
                      "ambiguous create: matched server item preserves the original contents")
        let recovered = try await harness.vault.outboxStatus()
        runner.expect(recovered.pendingCount, 0, "ambiguous create: confirmed operation is no longer queued")
        runner.expectTrue(recovered.issues.isEmpty, "ambiguous create: no manual action remains")
    } catch { runner.expectTrue(false, "ambiguous create regression threw: \(error)") }
}

private func conflictCipher(id: String, name: String, revision: Date, key: EncString? = nil,
                            deleted: Date? = nil) throws -> CipherResponse {
    let encrypt = key == nil ? Fixtures.enc : Fixtures.cipherEnc
    return CipherResponse(id: id, organizationId: nil, folderId: nil, type: .login,
                          name: try EncString(parsing: encrypt(name)), notes: nil, favorite: false, reprompt: 0,
                          edit: true, viewPassword: true, login: nil,
                          card: nil, identity: nil, secureNote: nil, sshKey: nil, fields: nil, attachments: nil,
                          collectionIds: nil, key: key, revisionDate: revision, creationDate: revision, deletedDate: deleted)
}

// MARK: - Shared setup

/// Make a harness and log in (vault unlocked, accountID available). Returns the harness +
/// the resolved accountID, or `nil` after recording a failure on `r`.
private func loggedInHarness(_ r: inout TestRunner,
                             cipherServer: ConflictTestServer? = nil) async -> (Fixtures.Harness, String)? {
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())], cipherServer: cipherServer) }
    catch { r.expectTrue(false, "makeHarness threw: \(error)"); return nil }
    do {
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                   server: Fixtures.server)
    } catch { r.expectTrue(false, "login threw: \(error)"); Fixtures.cleanup(h.dir); return nil }
    guard let id = await h.auth.session?.accountID else {
        r.expectTrue(false, "missing accountID after login"); Fixtures.cleanup(h.dir); return nil
    }
    return (h, id)
}

// MARK: - Offline outbox paths

/// createCipher offline (`.serverUnreachable`): enqueues an OutboxOp.create row in the REAL
/// VaultStore AND persists an optimistic local cipher row that decrypts back to plaintext.
func checkCreateCipherOffline(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    await h.api.setCreateError(NetworkingError.serverUnreachable)

    let plaintext = PlaintextCipher(
        type: CipherType.login.rawValue, name: "Offline Item", notes: "offline note",
        login: PlaintextCipher.Login(username: "carol", password: "p@ss",
                                     uris: [PlaintextCipher.Uri(uri: "https://offline.test")])
    )

    var localID = ""
    do {
        localID = try await h.vault.createCipher(plaintext)
        r.expectTrue(!localID.isEmpty, "createOffline: returns a local id")
    } catch {
        r.expectTrue(false, "createOffline: createCipher threw: \(error)"); return
    }

    // (a) An OutboxRow was enqueued (op=create, entity=cipher, entityID=localID).
    do {
        let outbox = try await h.store.outbox()
        r.expect(outbox.count, 1, "createOffline: one outbox row enqueued")
        if let row = outbox.first {
            r.expect(row.accountID, accountID, "createOffline: outbox account scoped")
            r.expect(row.opType, OutboxOp.create.rawValue, "createOffline: outbox op=create")
            r.expect(row.entityType, OutboxEntity.cipher.rawValue, "createOffline: outbox entity=cipher")
            r.expect(row.entityID, localID, "createOffline: outbox entityID=localID")
            r.expectTrue(!row.payloadJSON.isEmpty && row.payloadJSON != "{}",
                         "createOffline: outbox payload non-trivial")
            let payload = try OutboxCipherPayload.decode(row.payloadJSON)
            r.expect(try EncString(parsing: payload.name).type,
                     EncryptionType.aesCbc256_HmacSha256_B64,
                     "createOffline: queued payload uses decryptable type-2 encryption")
        }
    } catch { r.expectTrue(false, "createOffline: outbox() threw: \(error)") }

    // (b) The optimistic local row is retrievable and decrypts to the plaintext.
    do {
        let row = try await h.store.cipher(id: localID, accountID: accountID)
        r.expectTrue(row != nil, "createOffline: local row persisted")
        let cipher = try await h.vault.cipher(id: localID)
        r.expect(cipher.name, "Offline Item", "createOffline: local row name decrypts")
        r.expect(cipher.notes, "offline note", "createOffline: local row notes decrypt")
        r.expect(cipher.login?.username, "carol", "createOffline: local row username decrypts")
        r.expect(cipher.login?.password, "p@ss", "createOffline: local row password decrypts")
        r.expect(cipher.login?.uris.first?.uri, "https://offline.test", "createOffline: local row uri decrypts")
    } catch { r.expectTrue(false, "createOffline: local row retrieve/decrypt threw: \(error)") }
}

/// updateCipher offline: enqueues an OutboxOp.update row and persists the optimistic local row.
func checkUpdateCipherOffline(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    // Seed an existing row to update.
    do {
        try await h.store.upsertCiphers([
            CipherRow(id: "upd-1", accountID: accountID, type: CipherType.login.rawValue,
                      revisionDate: Fixtures.iso(Date()), creationDate: Fixtures.iso(Date()),
                      encName: Fixtures.enc("Before"))
        ])
    } catch { r.expectTrue(false, "updateOffline: seed threw: \(error)"); return }

    await h.api.setUpdateError(NetworkingError.serverUnreachable)

    let updated = PlaintextCipher(id: "upd-1", type: CipherType.login.rawValue, name: "After Offline",
                                  login: PlaintextCipher.Login(username: "dave"))
    do {
        try await h.vault.updateCipher(id: "upd-1", updated)
    } catch { r.expectTrue(false, "updateOffline: updateCipher threw: \(error)"); return }

    // Outbox enqueued with op=update, entityID=upd-1.
    do {
        let outbox = try await h.store.outbox()
        r.expect(outbox.count, 1, "updateOffline: one outbox row enqueued")
        if let row = outbox.first {
            r.expect(row.accountID, accountID, "updateOffline: outbox account scoped")
            r.expect(row.opType, OutboxOp.update.rawValue, "updateOffline: outbox op=update")
            r.expect(row.entityID, "upd-1", "updateOffline: outbox entityID")
            let payload = try OutboxCipherPayload.decode(row.payloadJSON)
            r.expect(try EncString(parsing: payload.name).type,
                     EncryptionType.aesCbc256_HmacSha256_B64,
                     "updateOffline: queued payload uses decryptable type-2 encryption")
        }
    } catch { r.expectTrue(false, "updateOffline: outbox() threw: \(error)") }

    // Optimistic local row reflects the new plaintext.
    do {
        let cipher = try await h.vault.cipher(id: "upd-1")
        r.expect(cipher.name, "After Offline", "updateOffline: local row updated name decrypts")
        r.expect(cipher.login?.username, "dave", "updateOffline: local row updated username decrypts")
    } catch { r.expectTrue(false, "updateOffline: local row decrypt threw: \(error)") }
}

/// deleteCipher offline: enqueues an OutboxOp.delete row and removes the local row.
func checkDeleteCipherOffline(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        try await h.store.upsertCiphers([
            CipherRow(id: "del-1", accountID: accountID, type: CipherType.login.rawValue,
                      revisionDate: Fixtures.iso(Date()), creationDate: Fixtures.iso(Date()),
                      deletedDate: Fixtures.iso(Date()), encName: Fixtures.enc("Doomed"))
        ])
    } catch { r.expectTrue(false, "deleteOffline: seed threw: \(error)"); return }

    await h.api.setDeleteError(NetworkingError.serverUnreachable)

    do {
        try await h.vault.permanentlyDeleteCipher(id: "del-1")
    } catch { r.expectTrue(false, "deleteOffline: deleteCipher threw: \(error)"); return }

    // Outbox enqueued with op=delete, entityID=del-1.
    do {
        let outbox = try await h.store.outbox()
        r.expect(outbox.count, 1, "deleteOffline: one outbox row enqueued")
        if let row = outbox.first {
            r.expect(row.accountID, accountID, "deleteOffline: outbox account scoped")
            r.expect(row.opType, OutboxOp.delete.rawValue, "deleteOffline: outbox op=delete")
            r.expect(row.entityID, "del-1", "deleteOffline: outbox entityID")
        }
    } catch { r.expectTrue(false, "deleteOffline: outbox() threw: \(error)") }

    // The local row is removed (best-effort delete after enqueue).
    do {
        let row = try await h.store.cipher(id: "del-1", accountID: accountID)
        r.expectTrue(row == nil, "deleteOffline: local row removed")
    } catch { r.expectTrue(false, "deleteOffline: cipher() threw: \(error)") }
}

// MARK: - Online update / delete round-trips

/// updateCipher online: encrypts + calls the fake API update + updates the store; the stored
/// row reflects the new plaintext and NO outbox row is enqueued.
func checkUpdateCipherOnline(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        try await h.store.upsertCiphers([
            CipherRow(id: "u-1", accountID: accountID, type: CipherType.login.rawValue,
                      revisionDate: Fixtures.iso(Date()), creationDate: Fixtures.iso(Date()),
                      encName: Fixtures.enc("Old Name"))
        ])
    } catch { r.expectTrue(false, "updateOnline: seed threw: \(error)"); return }

    let updated = PlaintextCipher(id: "u-1", type: CipherType.login.rawValue, name: "New Name",
                                  login: PlaintextCipher.Login(username: "erin", password: "newpw"))
    do {
        try await h.vault.updateCipher(id: "u-1", updated)
    } catch { r.expectTrue(false, "updateOnline: updateCipher threw: \(error)"); return }

    // Fake API recorded the update with an encrypted (type-2) name.
    let updates = await h.api.updatedRequests
    r.expect(updates.count, 1, "updateOnline: fake recorded one update")
    if let u = updates.first {
        r.expect(u.id, "u-1", "updateOnline: update id forwarded")
        r.expectTrue(u.req.name.stringValue.hasPrefix("2."), "updateOnline: name encrypted as type-2")
        r.expectTrue(!u.req.name.stringValue.contains("New Name"), "updateOnline: plaintext name NOT in request")
    }

    // Store updated; no outbox row.
    do {
        let cipher = try await h.vault.cipher(id: "u-1")
        r.expect(cipher.name, "New Name", "updateOnline: store reflects new name")
        r.expect(cipher.login?.username, "erin", "updateOnline: store reflects new username")
        let outbox = try await h.store.outbox()
        r.expect(outbox.count, 0, "updateOnline: no outbox row enqueued")
    } catch { r.expectTrue(false, "updateOnline: verify threw: \(error)") }
}

/// A personal item with a protected per-cipher key must keep that key and encrypt edited
/// fields with the unwrapped cipher key on the online request + server echo round-trip.
func checkPersonalCipherKeyUpdateOnline(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    let protectedKey = Fixtures.protectedCipherKey()

    do {
        try await h.store.upsertCiphers([
            CipherRow(id: "key-online", accountID: accountID, type: CipherType.login.rawValue,
                      revisionDate: Fixtures.iso(Date()), creationDate: Fixtures.iso(Date()),
                      encName: Fixtures.cipherEnc("Before"),
                      encBlob: blobJSON(username: Fixtures.cipherEnc("alice"),
                                        password: Fixtures.cipherEnc("old")),
                      encCipherKey: protectedKey.stringValue)
        ])
        var edited = try await h.vault.cipher(id: "key-online")
        r.expect(edited.protectedCipherKey, protectedKey,
                 "itemKey online: read exposes protected key metadata")
        edited.name = "After"
        edited.login?.password = "new"
        try await h.vault.updateCipher(id: "key-online", edited)

        guard let request = await h.api.updatedRequests.first?.req else {
            r.expectTrue(false, "itemKey online: update request recorded"); return
        }
        r.expect(request.key, protectedKey, "itemKey online: request preserves protected key")
        let requestName = try SymmetricCrypto.decrypt(request.name, using: Fixtures.cipherKey())
        r.expect(String(data: requestName, encoding: .utf8), "After",
                 "itemKey online: request fields use cipher key")

        let stored = try await h.store.cipher(id: "key-online", accountID: accountID)
        r.expect(stored?.encCipherKey, protectedKey.stringValue,
                 "itemKey online: server echo row preserves protected key")
        let roundTrip = try await h.vault.cipher(id: "key-online")
        r.expect(roundTrip.name, "After", "itemKey online: updated name decrypts")
        r.expect(roundTrip.login?.password, "new", "itemKey online: updated password decrypts")
    } catch {
        r.expectTrue(false, "itemKey online: round-trip threw: \(error)")
    }
}

/// The optimistic offline row and serialized outbox payload must preserve the same protected
/// key, so the local edit remains readable and a later flush sends correctly keyed ciphertext.
func checkPersonalCipherKeyUpdateOffline(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    let protectedKey = Fixtures.protectedCipherKey()

    do {
        try await h.store.upsertCiphers([
            CipherRow(id: "key-offline", accountID: accountID, type: CipherType.login.rawValue,
                      revisionDate: Fixtures.iso(Date()), creationDate: Fixtures.iso(Date()),
                      encName: Fixtures.cipherEnc("Before"),
                      encBlob: blobJSON(username: Fixtures.cipherEnc("bob")),
                      encCipherKey: protectedKey.stringValue)
        ])
        await h.api.setUpdateError(NetworkingError.serverUnreachable)
        var edited = try await h.vault.cipher(id: "key-offline")
        edited.name = "After Offline"
        edited.login?.username = "robert"
        try await h.vault.updateCipher(id: "key-offline", edited)

        let stored = try await h.store.cipher(id: "key-offline", accountID: accountID)
        r.expect(stored?.encCipherKey, protectedKey.stringValue,
                 "itemKey offline: optimistic row preserves protected key")
        let roundTrip = try await h.vault.cipher(id: "key-offline")
        r.expect(roundTrip.name, "After Offline", "itemKey offline: updated name decrypts")
        r.expect(roundTrip.login?.username, "robert",
                 "itemKey offline: updated username decrypts")

        guard let outbox = try await h.store.outbox().first else {
            r.expectTrue(false, "itemKey offline: outbox row exists"); return
        }
        let payload = try JSONDecoder().decode(OutboxCipherPayload.self,
                                               from: Data(outbox.payloadJSON.utf8))
        r.expect(payload.key, protectedKey.stringValue,
                 "itemKey offline: outbox preserves protected key")
        let queuedName = try EncString(parsing: payload.name)
        let queuedPlaintext = try SymmetricCrypto.decrypt(queuedName, using: Fixtures.cipherKey())
        r.expect(String(data: queuedPlaintext, encoding: .utf8), "After Offline",
                 "itemKey offline: queued fields use cipher key")
    } catch {
        r.expectTrue(false, "itemKey offline: round-trip threw: \(error)")
    }
}

/// Until organization keys are represented in `KeyVault`, never fall back to the personal
/// user key for an organization item: reject before the API or local row can be changed.
func checkOrganizationUpdateWithoutKeyIsRejected(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    let originalNameWire = Fixtures.enc("Organization Item")
    do {
        try await h.store.upsertCiphers([
            CipherRow(id: "org-no-key", accountID: accountID,
                      type: CipherType.login.rawValue, organizationID: "org-1",
                      revisionDate: Fixtures.iso(Date()), creationDate: Fixtures.iso(Date()),
                      encName: originalNameWire)
        ])
    } catch {
        r.expectTrue(false, "organization key guard: seed threw: \(error)"); return
    }

    let edited = PlaintextCipher(id: "org-no-key", type: CipherType.login.rawValue,
                                 name: "Must Not Write", organizationID: "org-1",
                                 login: .init(username: "alice"))
    await r.expectThrowsErrorAsync(
        RepositoryError.organizationCipherKeyUnavailable,
        "organization key guard: missing key is rejected"
    ) {
        try await h.vault.updateCipher(id: "org-no-key", edited)
    }
    r.expect((await h.api.updatedRequests).count, 0,
             "organization key guard: API update not called")
    do {
        r.expect((try await h.store.cipher(id: "org-no-key", accountID: accountID))?.encName,
                 originalNameWire,
                 "organization key guard: local row unchanged")
    } catch {
        r.expectTrue(false, "organization key guard: verify row threw: \(error)")
    }
}

/// deleteCipher online: calls the fake API delete + removes the local row; no outbox row.
func checkDeleteCipherOnline(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        try await h.store.upsertCiphers([
            CipherRow(id: "d-1", accountID: accountID, type: CipherType.login.rawValue,
                      revisionDate: Fixtures.iso(Date()), creationDate: Fixtures.iso(Date()),
                      deletedDate: Fixtures.iso(Date()), encName: Fixtures.enc("Gone Soon"))
        ])
    } catch { r.expectTrue(false, "deleteOnline: seed threw: \(error)"); return }

    do {
        try await h.vault.permanentlyDeleteCipher(id: "d-1")
    } catch { r.expectTrue(false, "deleteOnline: deleteCipher threw: \(error)"); return }

    // Fake API recorded the delete.
    let deleted = await h.api.deletedIDs
    r.expect(deleted, ["d-1"], "deleteOnline: fake recorded the delete id")

    // Local row removed; no outbox row.
    do {
        let row = try await h.store.cipher(id: "d-1", accountID: accountID)
        r.expectTrue(row == nil, "deleteOnline: local row removed")
        let outbox = try await h.store.outbox()
        r.expect(outbox.count, 0, "deleteOnline: no outbox row enqueued")
    } catch { r.expectTrue(false, "deleteOnline: verify threw: \(error)") }
}

func checkFolderAndTrashLifecycle(_ runner: inout TestRunner) async {
    guard let (harness, accountID) = await loggedInHarness(&runner) else { return }
    defer { Fixtures.cleanup(harness.dir) }
    do {
        let folderID = try await harness.vault.createFolder(name: "  Work  ")
        let cipherID = try await harness.vault.createCipher(PlaintextCipher(name: "Example", folderID: folderID))
        runner.expect(try await harness.vault.folders().first?.name, "Work", "folder names round-trip encrypted")
        try await harness.vault.renameFolder(id: folderID, name: "Team")
        runner.expect(try await harness.vault.folders().first?.name, "Team", "folder rename persists")
        try await harness.vault.deleteFolder(id: folderID)
        runner.expect(try await harness.vault.cipher(id: cipherID).folderID, nil, "removing a folder leaves its items unfiled")
        await runner.expectThrowsErrorAsync(RepositoryError.cipherNotFound, "permanent deletion requires a trashed item") {
            try await harness.vault.permanentlyDeleteCipher(id: cipherID)
        }
        try await harness.vault.changeCipherVisibility(id: cipherID, change: .trash)
        runner.expect(try await harness.vault.listing().trash.first?.id, cipherID, "trashed item retained for undo")
        runner.expect(try await harness.vault.search("example").count, 0, "trash is never searched")
        runner.expect(await harness.api.deletedIDs.count, 0, "moving to trash must never issue a hard delete")
        let row = try await harness.store.cipher(id: cipherID, accountID: accountID)
        runner.expectTrue(row?.encName != nil, "encrypted trash row remains intact")
        guard let request = await harness.api.createdRequests.last else {
            runner.expectTrue(false, "missing encrypted create response"); return
        }
        await harness.api.setUpdateReturn(FakeAPI.echo(request, id: cipherID))
        try await harness.vault.changeCipherVisibility(id: cipherID, change: .restore)
        runner.expect(try await harness.vault.cipher(id: cipherID).name, "Example", "restore makes the item accessible again")
        try await harness.vault.changeCipherVisibility(id: cipherID, change: .trash)
        try await harness.vault.permanentlyDeleteCipher(id: cipherID)
        runner.expect(try await harness.vault.trashedCiphers().count, 0, "permanent deletion removes the trash row")
    } catch { runner.expectTrue(false, "folder and trash lifecycle failed: \(error)") }
}

func checkStaleDraftDoesNotOverwriteNewerCipher(_ runner: inout TestRunner) async {
    guard let (harness, accountID) = await loggedInHarness(&runner) else { return }
    defer { Fixtures.cleanup(harness.dir) }
    let originalRevision = "2100-01-01T00:00:00.123Z"
    let syncedRevision = "2100-01-01T00:00:00.124Z"
    let cipherID = "changing-item"
    do {
        try await harness.store.upsertCiphers([CipherRow(id: cipherID, accountID: accountID, type: 1,
            revisionDate: originalRevision, creationDate: originalRevision, encName: Fixtures.enc("Original"))])
        var stale = try await harness.vault.cipher(id: cipherID)
        stale.name = "Unsaved edit"
        let newerBlob = """
        {"login":{"fido2Credentials":[{"credentialId":"\(Fixtures.enc("new credential"))"}]},
         "fields":[{"type":0,"name":"\(Fixtures.enc("new field"))"}]}
        """
        try await harness.store.upsertCiphers([CipherRow(id: cipherID, accountID: accountID, type: 1,
            revisionDate: syncedRevision, creationDate: originalRevision, encName: Fixtures.enc("Updated"), encBlob: newerBlob)])
        await runner.expectThrowsErrorAsync(RepositoryError.cipherChanged, "one-millisecond newer snapshot rejects editor write") {
            try await harness.vault.updateCipher(id: cipherID, stale)
        }
        let current = try await harness.vault.cipher(id: cipherID)
        runner.expect(current.login?.fido2Credentials.first?.credentialId, "new credential", "stale draft cannot remove a passkey")
        runner.expect(current.fields.first?.name, "new field", "stale draft cannot remove a custom field")
        runner.expect(await harness.api.updatedRequests.count, 0, "stale draft makes no request")
        runner.expect(try await harness.store.outbox(accountID: accountID).count, 0, "stale draft never enters the outbox")

        var favorite = current
        favorite.favorite = true
        await harness.api.setUpdateError(NetworkingError.serverUnreachable)
        try await harness.vault.updateCipher(id: cipherID, favorite)
        var next = try await harness.vault.cipher(id: cipherID)
        runner.expectTrue(next.favorite && next.revisionDate != current.revisionDate,
                          "offline revisions advance even when the server clock is ahead")
        await runner.expectThrowsErrorAsync(RepositoryError.cipherChanged, "offline stale draft cannot replace pending changes") {
            try await harness.vault.updateCipher(id: cipherID, favorite)
        }
        next.name = "Second local edit"
        try await harness.vault.updateCipher(id: cipherID, next)
        let queued = try await harness.store.outbox(accountID: accountID)
        runner.expect(queued.count, 1, "fresh offline edit coalesces")
        runner.expect(queued.first?.lastKnownRevisionDate, syncedRevision, "coalescing keeps the server base, not the local clock")
        await harness.api.setUpdateError(nil)
        _ = try await harness.syncEngine.flushOutbox(accountID: accountID)
        runner.expect(await harness.api.updatedRequests.last?.req.lastKnownRevisionDate, SyncEngine.parseDate(syncedRevision),
                      "flush sends the original server revision with milliseconds")
        runner.expect(try await harness.vault.cipher(id: cipherID).login?.fido2Credentials.first?.credentialId,
                      "new credential", "fresh edits preserve the synced passkey")
    } catch { runner.expectTrue(false, "stale draft regression failed: \(error)") }
}

// MARK: - refresh()

/// refresh(): a queued refresh response → the new access token is set and refresh() returns true.
func checkRefreshSuccess(_ r: inout TestRunner) async {
    guard let (h, _) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    // login persisted refresh token "refresh-1" in the keychain. Queue a new token response.
    let newToken = Fixtures.tokenResponse(accessToken: "access-2", refreshToken: "refresh-2")
    await h.api.setRefreshResponse(newToken)

    do {
        let ok = try await h.auth.refresh()
        r.expectTrue(ok, "refresh: returns true on success")
    } catch { r.expectTrue(false, "refresh: threw: \(error)"); return }

    let tokens = await h.api.accessTokensSet
    r.expectTrue(tokens.contains("access-2"), "refresh: new access token set on API client")
}

/// refresh() with a failing API (no refresh response queued → fake throws .unauthorized):
/// the source wraps it as RepositoryError.network and THROWS (it does not return false).
func checkRefreshFailureThrows(_ r: inout TestRunner) async {
    guard let (h, _) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    // No refreshResponse queued → FakeAPI.refresh throws NetworkingError.unauthorized,
    // which AuthRepository.refresh() wraps as RepositoryError.network(...). The `network`
    // factory is internal, so reconstruct the equivalent public `.underlying` value (kind
    // .network, description = String(describing: the wrapped error)).
    let expected = RepositoryError.underlying(kind: .network,
                                              description: String(describing: NetworkingError.unauthorized))
    await r.expectThrowsErrorAsync(expected, "refresh: failing API throws RepositoryError.network") {
        _ = try await h.auth.refresh()
    }
}

/// refresh() with no stored refresh token throws .notAuthenticated (logout cleared it).
func checkRefreshNoTokenThrows(_ r: inout TestRunner) async {
    guard let (h, _) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    await h.auth.logout()  // deletes the stored refresh token

    await r.expectThrowsErrorAsync(RepositoryError.notAuthenticated,
                                   "refresh: no stored token throws .notAuthenticated") {
        _ = try await h.auth.refresh()
    }
}

/// Refresh tokens are namespaced by canonical account id. Switching servers must never send
/// the previous account's token to the newly selected environment.
func checkRefreshTokenIsAccountScoped(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do {
        h = try await Fixtures.makeHarness(tokenResults: [
            .success(Fixtures.tokenResponse(accessToken: "access-a", refreshToken: "refresh-a")),
            .success(Fixtures.tokenResponse(accessToken: "access-b", refreshToken: "refresh-b")),
        ])
    } catch { r.expectTrue(false, "scoped refresh: makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    let serverB = ServerEnvironment(string: "https://other.example.test")!
    do {
        _ = try await h.auth.login(
            email: Fixtures.email,
            password: Fixtures.password,
            server: Fixtures.server
        )
        let accountA = await h.auth.session!.accountID
        _ = try await h.auth.login(
            email: Fixtures.email,
            password: Fixtures.password,
            server: serverB
        )
        let accountB = await h.auth.session!.accountID

        let storedA = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.refreshToken(accountID: accountA)
        )
        let storedB = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.refreshToken(accountID: accountB)
        )
        r.expect(String(data: storedA ?? Data(), encoding: .utf8), "refresh-a",
                 "scoped refresh: account A token remains in A namespace")
        r.expect(String(data: storedB ?? Data(), encoding: .utf8), "refresh-b",
                 "scoped refresh: account B token is in B namespace")

        await h.api.setRefreshResponse(
            Fixtures.tokenResponse(accessToken: "access-b2", refreshToken: "refresh-b2")
        )
        _ = try await h.auth.refresh()
        r.expect(await h.api.refreshTokensUsed.last, "refresh-b",
                 "scoped refresh: active B environment receives only B token")
        r.expect(await h.api.refreshServers.last, serverB,
                 "scoped refresh: request is explicitly bound to B server")
    } catch {
        r.expectTrue(false, "scoped refresh flow threw: \(error)")
    }
}

// MARK: - logout()

/// logout(): locks the KeyVault + encryptor, clears the session, drops the bearer token, and
/// deletes the stored secrets — so a subsequent master-password unlock cannot run (no session)
/// and the vault stays locked.
func checkLogout(_ r: inout TestRunner) async {
    guard let (h, _) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }

    // Sanity: unlocked + has session before logout.
    let unlockedBefore = await h.keyVault.isUnlocked
    r.expectTrue(unlockedBefore, "logout: unlocked before")

    await h.auth.logout()

    // KeyVault + encryptor cleared.
    let unlockedAfter = await h.keyVault.isUnlocked
    r.expectTrue(!unlockedAfter, "logout: KeyVault locked after logout")
    let authUnlocked = await h.auth.isUnlocked()
    r.expectTrue(!authUnlocked, "logout: auth.isUnlocked() false after logout")

    // Session cleared.
    let session = await h.auth.session
    r.expectTrue(session == nil, "logout: session cleared")
    let activeSessionMarker = try? await h.keychain.getSecret(
        account: AppShared.KeychainAccount.activeSessionID
    )
    r.expectTrue(activeSessionMarker == nil,
                 "logout: shared extension session nonce deleted")

    // Bearer token dropped (nil pushed to the API client).
    let tokens = await h.api.accessTokensSet
    r.expectTrue(tokens.last == .some(nil), "logout: bearer token cleared (nil set)")

    // Stored secrets deleted: the refresh token is gone (refresh now fails as notAuthenticated),
    // and master-password unlock can't run because the session is gone.
    await r.expectThrowsErrorAsync(RepositoryError.notAuthenticated,
                                   "logout: refresh after logout throws .notAuthenticated (token deleted)") {
        _ = try await h.auth.refresh()
    }
    await r.expectThrowsErrorAsync(RepositoryError.notAuthenticated,
                                   "logout: unlockWithMasterPassword after logout throws .notAuthenticated") {
        try await h.auth.unlockWithMasterPassword(Fixtures.password)
    }
}

/// Offline create followed by edits must remain one create payload; after the server assigns
/// an id, the local placeholder alias resolves to the final row without a PUT to the placeholder.
func checkOfflineCreateUpdateCoalesces(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    await h.api.setCreateError(NetworkingError.serverUnreachable)

    do {
        let localID = try await h.vault.createCipher(PlaintextCipher(
            type: CipherType.login.rawValue,
            name: "Draft",
            login: .init(username: "alice", password: "one")
        ))
        let createAttemptsBeforeFlush = await h.api.createdRequests.count
        await h.api.setCreateError(nil)
        try await h.vault.updateCipher(id: localID, PlaintextCipher(
            id: localID,
            type: CipherType.login.rawValue,
            name: "Final",
            login: .init(username: "alice", password: "two")
        ))

        let queued = try await h.store.outbox(accountID: accountID)
        r.expect(queued.count, 1, "offline create+update: one outbox row")
        r.expect(queued.first?.opType, "create",
                 "offline create+update: operation remains create")
        let outcome = try await h.syncEngine.flushOutbox(accountID: accountID)
        r.expect(outcome.flushed, 1, "offline create+update: latest create flushes")
        r.expect(await h.api.createdRequests.count, createAttemptsBeforeFlush + 1,
                 "offline create+update: flush makes one additional POST")
        r.expect(await h.api.updatedRequests.count, 0,
                 "offline create+update: no PUT to placeholder")
        let final = try await h.vault.cipher(id: localID)
        r.expect(final.name, "Final",
                 "offline create+update: placeholder alias resolves latest payload")
    } catch {
        r.expectTrue(false, "offline create+update threw: \(error)")
    }
}

/// Deleting an unsent create cancels it atomically; no server item may later resurrect.
func checkOfflineCreateDeleteCancels(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    await h.api.setCreateError(NetworkingError.serverUnreachable)

    do {
        let localID = try await h.vault.createCipher(PlaintextCipher(
            type: CipherType.login.rawValue,
            name: "Discard me"
        ))
        let createAttemptsBeforeDelete = await h.api.createdRequests.count
        await h.api.setCreateError(nil)
        try await h.store.setCipherVisibility(id: localID, accountID: accountID, deletedDate: Fixtures.iso(Date()), archivedDate: nil)
        try await h.vault.permanentlyDeleteCipher(id: localID)
        r.expect(try await h.store.outbox(accountID: accountID).count, 0,
                 "offline create+delete: create and delete cancel")
        r.expectTrue(try await h.store.cipher(
            id: localID,
            accountID: accountID
        ) == nil, "offline create+delete: optimistic row deleted")
        _ = try await h.syncEngine.flushOutbox(accountID: accountID)
        r.expect(await h.api.createdRequests.count, createAttemptsBeforeDelete,
                 "offline create+delete: no later POST")
        r.expect(await h.api.deletedIDs.count, 0,
                 "offline create+delete: no DELETE to placeholder")
    } catch {
        r.expectTrue(false, "offline create+delete threw: \(error)")
    }
}

/// A user edit that begins while create POST is paused waits for finalization, resolves the
/// server id alias, then updates the real server row. It cannot mutate the in-flight outbox row.
func checkMutationWaitsForInFlightCreate(_ r: inout TestRunner) async {
    guard let (h, _) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    await h.api.setCreateError(NetworkingError.serverUnreachable)

    do {
        let localID = try await h.vault.createCipher(PlaintextCipher(
            type: CipherType.login.rawValue,
            name: "Before"
        ))
        let createAttemptsBeforeFlush = await h.api.createdRequests.count
        await h.api.setCreateError(nil)
        await h.api.pauseNextCreate()
        let flush = Task { try await h.syncEngine.flushOutbox(
            accountID: (await h.auth.session)!.accountID
        ) }
        await h.api.waitUntilCreateIsPaused()
        let update = Task {
            try await h.vault.updateCipher(id: localID, PlaintextCipher(
                id: localID,
                type: CipherType.login.rawValue,
                name: "After"
            ))
        }
        await Task.yield()
        r.expect(await h.api.updatedRequests.count, 0,
                 "in-flight create: update waits behind coordinator")
        await h.api.resumePausedCreate()
        _ = try await flush.value
        try await update.value

        r.expect(await h.api.createdRequests.count, createAttemptsBeforeFlush + 1,
                 "in-flight create: one additional POST")
        r.expect(await h.api.updatedRequests.first?.id,
                 "server-id-\(createAttemptsBeforeFlush + 1)",
                 "in-flight create: queued UI edit targets server id")
        r.expect(try await h.vault.cipher(id: localID).name, "After",
                 "in-flight create: alias returns final edit")
    } catch {
        r.expectTrue(false, "in-flight create race threw: \(error)")
    }
}

/// Refresh grants are serialized because rotating refresh tokens cannot safely be raced.
func checkConcurrentRefreshesAreSerialized(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    await h.api.setRefreshResponse(Fixtures.tokenResponse(
        accessToken: "access-refreshed",
        refreshToken: "refresh-2"
    ))
    await h.api.pauseNextRefresh()

    let first = Task { try await h.auth.refresh() }
    await h.api.waitUntilRefreshIsPaused()
    let second = Task { try await h.auth.refresh() }
    await Task.yield()
    r.expect(await h.api.refreshTokensUsed, ["refresh-1"],
             "concurrent refresh: second grant waits")
    await h.api.resumePausedRefresh()
    do {
        _ = try await first.value
        _ = try await second.value
        r.expect(await h.api.refreshTokensUsed, ["refresh-1", "refresh-2"],
                 "concurrent refresh: second grant uses rotated token")
        let stored = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.refreshToken(accountID: accountID)
        )
        r.expect(String(data: stored ?? Data(), encoding: .utf8), "refresh-2",
                 "concurrent refresh: latest valid token remains durable")
    } catch {
        r.expectTrue(false, "concurrent refresh threw: \(error)")
    }
}

/// A server pull and CRUD share the same coordinator. Delete cannot complete and then be
/// resurrected by a stale sync response that was already in flight.
func checkDeleteWaitsForInFlightFullSync(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    let response = Fixtures.syncResponse(
        cipherID: "sync-delete-race",
        name: "Race",
        username: "alice",
        uri: "https://race.example"
    )
    await h.api.setSyncResponse(response)
    do {
        _ = try await h.vault.sync()
        await h.api.pauseNextSync()
        let sync = Task { try await h.vault.sync() }
        await h.api.waitUntilSyncIsPaused()
        let delete = Task {
            try await h.vault.changeCipherVisibility(id: "sync-delete-race", change: .trash)
            try await h.vault.permanentlyDeleteCipher(id: "sync-delete-race")
        }
        await Task.yield()
        r.expect(await h.api.deletedIDs.count, 0,
                 "sync/delete race: delete waits for pull")
        await h.api.resumePausedSync()
        _ = try await sync.value
        try await delete.value
        r.expectTrue(try await h.store.cipher(
            id: "sync-delete-race",
            accountID: accountID
        ) == nil, "sync/delete race: final local state is deleted")
        r.expect(await h.api.deletedIDs, ["sync-delete-race"],
                 "sync/delete race: real server id deleted once")
    } catch {
        r.expectTrue(false, "sync/delete race threw: \(error)")
    }
}

func checkLockWaitsForRefreshRotation(_ r: inout TestRunner) async {
    guard let (h, accountID) = await loggedInHarness(&r) else { return }
    defer { Fixtures.cleanup(h.dir) }
    await h.api.setRefreshResponse(Fixtures.tokenResponse(
        accessToken: "access-after-lock-race",
        refreshToken: "refresh-after-lock-race"
    ))
    await h.api.pauseNextRefresh()
    let refresh = Task { try await h.auth.refresh() }
    await h.api.waitUntilRefreshIsPaused()
    await h.auth.lock()
    r.expectTrue(!(await h.keyVault.isUnlocked), "refresh/lock: lock completes before the remote response")
    await h.api.resumePausedRefresh()
    await r.expectThrowsAsync("refresh/lock: late refresh does not authorize the locked vault") { _ = try await refresh.value }
    do {
        let token = try await h.keychain.getSecret(
            account: AppShared.KeychainAccount.refreshToken(accountID: accountID)
        )
        r.expect(String(data: token ?? Data(), encoding: .utf8),
                 "refresh-after-lock-race",
                 "refresh/lock: rotated token is durable before lock completes")
        r.expectTrue(!(await h.keyVault.isUnlocked),
                     "refresh/lock: vault ends locked")
    } catch {
        r.expectTrue(false, "refresh/lock race threw: \(error)")
    }
}
