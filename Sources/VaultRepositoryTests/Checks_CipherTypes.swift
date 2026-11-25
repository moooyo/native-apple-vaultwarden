import Foundation
import CryptoCore
import VaultModels
import VaultStore
import Networking
import SyncEngine
import VaultRepository

/// All five cipher types must survive the real repository encryption -> local blob ->
/// decryption path and the offline outbox mirror without dropping untouched fields.
func checkAllCipherTypesRoundTrip(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do {
        h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())])
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password,
                                   server: Fixtures.server)
    } catch {
        r.expectTrue(false, "five types: setup threw \(error)")
        return
    }
    defer { Fixtures.cleanup(h.dir) }
    guard await h.auth.session?.accountID != nil else {
        r.expectTrue(false, "five types: missing account id")
        return
    }

    let metadataDate = Date(timeIntervalSinceReferenceDate: 789_123)
    let ciphers: [PlaintextCipher] = [
        PlaintextCipher(
            type: CipherType.login.rawValue,
            name: "Full Login",
            notes: "login note",
            favorite: true,
            login: .init(
                username: "alice",
                password: "correct horse",
                totp: "otpauth://totp/Tessera",
                uris: [.init(uri: "https://login-roundtrip.example", match: 3)],
                fido2Credentials: [.init(
                    credentialId: "credential-id", keyType: "public-key",
                    keyAlgorithm: "ECDSA", keyCurve: "P-256", keyValue: "pkcs8-value",
                    rpId: "login-roundtrip.example", rpName: "Round Trip",
                    userHandle: "user-handle", userName: "alice",
                    userDisplayName: "Alice Example", counter: "7",
                    discoverable: "true", creationDate: metadataDate
                )],
                passwordRevisionDate: metadataDate
            ),
            fields: [.init(type: FieldType.hidden.rawValue, name: "Login custom",
                           value: "custom secret", linkedId: nil)]
        ),
        PlaintextCipher(
            type: CipherType.secureNote.rawValue,
            name: "Full Secure Note",
            notes: "the complete secure note",
            secureNote: .init(type: SecureNoteType.generic.rawValue)
        ),
        PlaintextCipher(
            type: CipherType.card.rawValue,
            name: "Full Card",
            card: .init(cardholderName: "Ada Cardholder", brand: "Visa",
                        number: "4111111111111111", expMonth: "12", expYear: "2031",
                        code: "123"),
            fields: [.init(type: FieldType.linked.rawValue, name: "Card custom",
                           value: "linked value", linkedId: 7)]
        ),
        PlaintextCipher(
            type: CipherType.identity.rawValue,
            name: "Full Identity",
            identity: .init(
                title: "Dr", firstName: "Grace", middleName: "B", lastName: "Hopper",
                address1: "1 Compiler Way", address2: "Suite 2", address3: "Floor 3",
                city: "Arlington", state: "VA", postalCode: "22201", country: "US",
                company: "Navy", email: "grace.identity@example.test", phone: "+1 555 0100",
                ssn: "000-00-0000", username: "ghopper", passportNumber: "P123",
                licenseNumber: "L456"
            )
        ),
        PlaintextCipher(
            type: CipherType.sshKey.rawValue,
            name: "Full SSH Key",
            sshKey: .init(privateKey: "-----BEGIN PRIVATE KEY-----private",
                          publicKey: "ssh-ed25519 AAAA-roundtrip",
                          keyFingerprint: "SHA256:ssh-roundtrip-fingerprint")
        ),
    ]

    await h.api.setCreateError(NetworkingError.serverUnreachable)
    var ids: [String] = []
    for original in ciphers {
        do {
            let id = try await h.vault.createCipher(original)
            ids.append(id)
            var expected = original
            expected.id = id
            let actual = try await h.vault.cipher(id: id)
            expected.revisionDate = actual.revisionDate
            expected.creationDate = actual.creationDate
            r.expectTrue(actual.protectedCipherKey != nil, "new item has its own wrapped key")
            expected.protectedCipherKey = actual.protectedCipherKey
            r.expectTrue(actual.revisionDate != nil && actual.creationDate != nil, "offline items expose dates for sorting")
            r.expect(actual, expected, "five types: \(original.name) local round-trip")
        } catch {
            r.expectTrue(false, "five types: \(original.name) create/read threw \(error)")
        }
    }

    let requests = await h.api.createdRequests
    r.expect(requests.count, 5, "five types: API saw every create")
    if requests.count == 5 {
        r.expectTrue(requests[0].login?.fido2Credentials?.first?.keyValue != nil,
                     "five types: login request preserves passkey private key")
        r.expect(requests[1].secureNote?.type, SecureNoteType.generic.rawValue,
                 "five types: secure-note payload present")
        r.expectTrue(requests[2].card?.code != nil,
                     "five types: card request preserves code")
        r.expectTrue(requests[3].identity?.licenseNumber != nil,
                     "five types: identity request preserves final field")
        r.expectTrue(requests[4].sshKey?.privateKey != nil,
                     "five types: SSH request preserves private key")
        r.expect(requests[2].fields?.first?.linkedId, 7,
                 "five types: linked custom-field id preserved")
    }

    // Repeat the matrix online. FakeAPI echoes every encrypted sub-payload as a server
    // response, exercising makeRow/encodeBlob rather than the optimistic local-row path.
    await h.api.setCreateError(nil)
    var onlineIDs: [String] = []
    for original in ciphers {
        do {
            let id = try await h.vault.createCipher(original)
            onlineIDs.append(id)
            var expected = original
            expected.id = id
            let actual = try await h.vault.cipher(id: id)
            expected.revisionDate = actual.revisionDate
            expected.creationDate = actual.creationDate
            r.expectTrue(actual.protectedCipherKey != nil, "new item has its own wrapped key")
            expected.protectedCipherKey = actual.protectedCipherKey
            r.expectTrue(actual.revisionDate != nil && actual.creationDate != nil, "online items expose server dates")
            r.expect(actual, expected, "five types online: \(original.name) round-trip")
        } catch {
            r.expectTrue(false, "five types online: \(original.name) create/read threw \(error)")
        }
    }

    do {
        let rows = try await h.store.outbox()
        r.expect(rows.count, 5, "five types: every offline create queued")
        let payloads = try rows.map { try OutboxCipherPayload.decode($0.payloadJSON) }
        let rebuilt = try payloads.map { try $0.cipherRequest(lastKnownRevisionDate: nil) }
        r.expectTrue(rebuilt.contains { $0.card?.number != nil && $0.card?.code != nil },
                     "five types: card survives outbox rebuild")
        r.expectTrue(rebuilt.contains { $0.identity?.passportNumber != nil && $0.identity?.licenseNumber != nil },
                     "five types: identity survives outbox rebuild")
        r.expectTrue(rebuilt.contains { $0.sshKey?.privateKey != nil && $0.sshKey?.keyFingerprint != nil },
                     "five types: SSH survives outbox rebuild")
        r.expectTrue(rebuilt.contains { $0.login?.fido2Credentials?.first?.userHandle != nil },
                     "five types: passkey survives outbox rebuild")
    } catch {
        r.expectTrue(false, "five types: outbox decode/rebuild threw \(error)")
    }

    do {
        r.expect((try await h.vault.search("ada cardholder")).first?.type,
                 CipherType.card.rawValue, "five types: card fields searchable")
        r.expect((try await h.vault.search("grace.identity@example.test")).first?.type,
                 CipherType.identity.rawValue, "five types: identity fields searchable")
        r.expect((try await h.vault.search("ssh-roundtrip-fingerprint")).first?.type,
                 CipherType.sshKey.rawValue, "five types: SSH fingerprint searchable")
        r.expectTrue(try await h.vault.search("4111111111111111").isEmpty,
                     "five types: card number excluded from transient search")
        r.expectTrue(try await h.vault.search("ssh-ed25519").isEmpty,
                     "five types: SSH public key excluded from transient search")
        r.expectTrue(try await h.vault.search("begin private key").isEmpty,
                     "five types: SSH private key excluded from transient search")
    } catch {
        r.expectTrue(false, "five types: search threw \(error)")
    }

    // Updating only the card's name must carry its full existing sub-payload forward.
    if ids.count > 2 {
        do {
            var edited = try await h.vault.cipher(id: ids[2])
            let originalCard = edited.card
            edited.name = "Renamed Card"
            await h.api.setUpdateError(NetworkingError.serverUnreachable)
            try await h.vault.updateCipher(id: ids[2], edited)
            let after = try await h.vault.cipher(id: ids[2])
            r.expect(after.card, originalCard, "five types: rename does not clear card fields")
        } catch {
            r.expectTrue(false, "five types: card-preserving update threw \(error)")
        }
    }


    if onlineIDs.count > 3 {
        do {
            var edited = try await h.vault.cipher(id: onlineIDs[3])
            let originalIdentity = edited.identity
            edited.name = "Renamed Identity"
            await h.api.setUpdateError(nil)
            try await h.vault.updateCipher(id: onlineIDs[3], edited)
            let after = try await h.vault.cipher(id: onlineIDs[3])
            r.expect(after.identity, originalIdentity,
                     "five types online: rename does not clear identity fields")
        } catch {
            r.expectTrue(false, "five types online: identity-preserving update threw \(error)")
        }
    }
}

func checkIncompleteSSHKeysAreRejected(_ runner: inout TestRunner) async {
    do {
        let harness = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())])
        defer { Fixtures.cleanup(harness.dir) }
        _ = try await harness.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        guard let lease = await harness.auth.currentSessionLease() else {
            runner.expectTrue(false, "SSH key validation: missing authenticated session")
            return
        }
        let complete = PlaintextCipher.SshKey(privateKey: " synthetic private key\n", publicKey: "synthetic public key",
                                               keyFingerprint: "synthetic fingerprint")
        let keyItem = PlaintextCipher(type: CipherType.sshKey.rawValue, name: "Synthetic SSH Key", sshKey: complete)
        let cipherID = try await harness.vault.createCipher(keyItem)
        let original = try await harness.vault.cipher(id: cipherID)
        runner.expect(original.sshKey, complete, "SSH key validation: all fields and significant whitespace preserved")

        await harness.api.setCreateError(NetworkingError.serverUnreachable)
        let pendingID = try await harness.vault.createCipher(keyItem)
        await harness.api.setCreateError(nil)
        let pending = try await harness.vault.cipher(id: pendingID)
        let queued = try await harness.store.outbox(accountID: lease.accountID)
        runner.expect(queued.count, 1, "SSH key validation: a complete offline item is queued")

        var missingPrivate = complete
        missingPrivate.privateKey = nil
        var blankPublic = complete
        blankPublic.publicKey = " \t\u{2003}\n"
        var blankFingerprint = complete
        blankFingerprint.keyFingerprint = ""
        let invalid: [(description: String, key: PlaintextCipher.SshKey?)] = [
            ("missing key payload", nil), ("missing private key", missingPrivate),
            ("whitespace-only public key", blankPublic), ("empty fingerprint", blankFingerprint)
        ]
        let creates = await harness.api.createdRequests.count
        let updates = await harness.api.updatedRequests.count
        for (description, key) in invalid {
            var malformed = keyItem
            malformed.sshKey = key
            var edited = original
            edited.sshKey = key
            var pendingEdit = pending
            pendingEdit.sshKey = key
            await runner.expectThrowsErrorAsync(RepositoryError.incompleteSSHKey, "SSH key validation: create rejects \(description)") {
                _ = try await harness.vault.createCipher(malformed)
            }
            await runner.expectThrowsErrorAsync(RepositoryError.incompleteSSHKey, "SSH key validation: update rejects \(description)") {
                try await harness.vault.updateCipher(id: cipherID, edited)
            }
            await runner.expectThrowsErrorAsync(RepositoryError.incompleteSSHKey, "SSH key validation: queued edit rejects \(description)") {
                try await harness.vault.updateCipher(id: pendingID, pendingEdit)
            }
        }
        await runner.expectThrowsErrorAsync(RepositoryError.incompleteSSHKey, "SSH key validation: import validates beyond the first item") {
            let invalidItem = PlaintextCipher(type: CipherType.sshKey.rawValue, name: "Invalid import", sshKey: missingPrivate)
            try await harness.vault.importCiphers([PlaintextCipher(name: "Valid import prefix"), invalidItem], expectedSession: lease)
        }
        runner.expect(await harness.api.createdRequests.count, creates, "SSH key validation: invalid creates and batch never reach the server")
        runner.expect(await harness.api.updatedRequests.count, updates, "SSH key validation: invalid updates never reach the server")
        runner.expect(try await harness.store.outbox(accountID: lease.accountID), queued,
                      "SSH key validation: attempts never mutate existing outbox operations")
        runner.expect(try await harness.vault.ciphers().count, 2, "SSH key validation: no optimistic partial create or import")
        runner.expect(try await harness.vault.cipher(id: cipherID), original, "SSH key validation: online row unchanged")
        runner.expect(try await harness.vault.cipher(id: pendingID), pending, "SSH key validation: offline row unchanged")
    } catch { runner.expectTrue(false, "SSH key validation: fixture threw \(error)") }
}

func checkIncompleteSSHKeyConflictCannotBeCopied(_ runner: inout TestRunner) async {
    do {
        let harness = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())])
        defer { Fixtures.cleanup(harness.dir) }
        _ = try await harness.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        guard let lease = await harness.auth.currentSessionLease() else {
            runner.expectTrue(false, "SSH key conflict: missing authenticated session")
            return
        }
        let cipherID = "incomplete-ssh-key"
        let oldKey = CipherRequest(type: CipherType.sshKey.rawValue, name: try EncString(parsing: Fixtures.enc("Old SSH Key")))
        let remote = FakeAPI.echo(oldKey, id: cipherID)
        await harness.api.setSyncResponse(try Fixtures.syncResponse(ciphers: [remote]))
        try await harness.vault.sync()
        let item = try await harness.vault.cipher(id: cipherID)
        runner.expect(item.name, "Old SSH Key", "SSH key conflict: incomplete server rows still decrypt for inspection")
        runner.expectTrue(item.sshKey?.isComplete != true, "SSH key conflict: read does not invent missing fields")

        let issueID = try await harness.store.enqueueOutbox(.init(accountID: lease.accountID, opType: OutboxOp.update.rawValue,
            entityType: OutboxEntity.cipher.rawValue, entityID: cipherID, payloadJSON: "{}", issue: .updateConflict))
        guard let issue = try await harness.vault.outboxStatus().issues.first, issue.id == issueID else {
            runner.expectTrue(false, "SSH key conflict: expected queued issue")
            return
        }
        runner.expectTrue(!issue.canKeepLocalCopy, "SSH key conflict: invalid copy is not offered")
        let queued = try await harness.store.outbox(accountID: lease.accountID)
        let reads = await harness.api.syncCallCount
        await runner.expectThrowsErrorAsync(RepositoryError.incompleteSSHKey, "SSH key conflict: invalid copy is rejected directly") {
            try await harness.vault.resolveOutboxIssue(issue, action: .keepLocalCopy)
        }
        runner.expect(await harness.api.syncCallCount, reads, "SSH key conflict: invalid copy starts no server read")
        runner.expect(try await harness.store.outbox(accountID: lease.accountID), queued, "SSH key conflict: invalid copy leaves the old issue intact")

        try await harness.vault.resolveOutboxIssue(issue, action: .useServer)
        runner.expectTrue(try await harness.store.outbox(accountID: lease.accountID).isEmpty, "SSH key conflict: adopting server state remains available")
        runner.expect(try await harness.vault.cipher(id: cipherID), item, "SSH key conflict: server state remains readable after resolution")
        try await harness.vault.changeCipherVisibility(id: cipherID, change: .trash)
        runner.expect(try await harness.vault.trashedCiphers().map(\.id), [cipherID], "SSH key conflict: incomplete items can still be trashed")
        try await harness.vault.permanentlyDeleteCipher(id: cipherID)
        runner.expect(await harness.api.deletedIDs, [cipherID], "SSH key conflict: incomplete items can still be removed")
    } catch { runner.expectTrue(false, "SSH key conflict: fixture threw \(error)") }
}
