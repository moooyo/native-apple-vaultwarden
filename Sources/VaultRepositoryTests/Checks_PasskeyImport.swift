import Foundation
import VaultModels
import VaultStore
import Networking
import VaultRepository

func checkPasskeyRegistrationImportIsIdempotent(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())]) }
    catch { r.expectTrue(false, "passkey import: makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        _ = try await h.auth.login(
            email: Fixtures.email,
            password: Fixtures.password,
            server: Fixtures.server
        )
        let accountID = await h.auth.session!.accountID
        let cipherID = try await h.vault.createCipher(PlaintextCipher(
            name: "Existing Login",
            login: .init(username: "alice")
        ))
        let credentialID = Data([0xfb, 0xff, 0x00, 0x01])
        let userHandle = Data([0xfa, 0x10, 0x20])
        let pkcs8 = Data([0x30, 0x82, 0x01, 0x02])
        let createdAt = Date(timeIntervalSince1970: 1_700_000_000)

        try await h.vault.importPasskeyRegistration(
            registrationID: "11111111-1111-4111-8111-111111111111",
            expectedAccountID: accountID,
            cipherID: cipherID,
            relyingPartyID: "example.test",
            userName: "alice",
            userDisplayName: "Alice",
            userHandle: userHandle,
            credentialID: credentialID,
            privateKeyPKCS8: pkcs8,
            creationDate: createdAt
        )
        let imported = try await h.vault.cipher(id: cipherID)
        let passkey = imported.login?.fido2Credentials.first
        r.expect(passkey?.credentialId, "b64.-_8AAQ",
                 "passkey import: credential id uses Bitwarden b64 base64url")
        r.expect(passkey?.keyValue, "MIIBAg",
                 "passkey import: PKCS#8 uses unpadded base64url")
        r.expect(passkey?.userHandle, "-hAg",
                 "passkey import: user handle uses unpadded base64url")
        r.expect(passkey?.keyType, "public-key", "passkey import: key type")
        r.expect(passkey?.keyAlgorithm, "ECDSA", "passkey import: key algorithm")
        r.expect(passkey?.keyCurve, "P-256", "passkey import: key curve")
        r.expect(passkey?.counter, "0", "passkey import: initial counter")
        r.expect(passkey?.discoverable, "true", "passkey import: discoverable")

        let updateCount = await h.api.updatedRequests.count
        try await h.vault.importPasskeyRegistration(
            registrationID: "11111111-1111-4111-8111-111111111111",
            expectedAccountID: accountID,
            cipherID: cipherID,
            relyingPartyID: "example.test",
            userName: "alice",
            userDisplayName: "Alice",
            userHandle: userHandle,
            credentialID: credentialID,
            privateKeyPKCS8: pkcs8,
            creationDate: createdAt
        )
        r.expect(await h.api.updatedRequests.count, updateCount,
                 "passkey import: replay does not issue another update")

        let newCredentialID = Data([9, 8, 7, 6])
        try await h.vault.importPasskeyRegistration(
            registrationID: "22222222-2222-4222-8222-222222222222",
            expectedAccountID: accountID,
            cipherID: nil,
            relyingPartyID: "new.example.test",
            userName: "new-user",
            userDisplayName: nil,
            userHandle: Data([5, 4, 3]),
            credentialID: newCredentialID,
            privateKeyPKCS8: pkcs8,
            creationDate: createdAt
        )
        let createCount = await h.api.createdRequests.count
        try await h.vault.importPasskeyRegistration(
            registrationID: "22222222-2222-4222-8222-222222222222",
            expectedAccountID: accountID,
            cipherID: nil,
            relyingPartyID: "new.example.test",
            userName: "new-user",
            userDisplayName: nil,
            userHandle: Data([5, 4, 3]),
            credentialID: newCredentialID,
            privateKeyPKCS8: pkcs8,
            creationDate: createdAt
        )
        r.expect(await h.api.createdRequests.count, createCount,
                 "passkey import: create replay finds existing raw credential id")

        // Flush both receipt-linked writes. The fixture intentionally has no sync
        // response, so `sync()` throws only after flushOutbox has committed its results.
        // The create response replaces the deterministic local placeholder with a new
        // server id; replay must still be a no-op and must not recreate the placeholder.
        do {
            _ = try await h.vault.sync()
            r.expectTrue(false, "passkey import: missing pull response should throw after flush")
        } catch {
            // Expected: the outbox flush succeeded, then the unavailable pull failed.
        }
        let serverID = "server-id-\(createCount + 1)"
        r.expect(await h.api.createdRequests.count, createCount + 1,
                 "passkey import: queued create reaches API exactly once")
        r.expect(try await h.store.outbox(accountID: accountID).count, 0,
                 "passkey import: successful flush clears linked writes")
        r.expectTrue(try await h.store.cipher(
            id: "passkey-22222222-2222-4222-8222-222222222222",
            accountID: accountID
        ) == nil, "passkey import: server id replaces local placeholder")
        let serverItem = try await h.vault.cipher(id: serverID)
        r.expect(serverItem.login?.fido2Credentials.first?.credentialId,
                 "b64.CQgHBg",
                 "passkey import: server-id row keeps registered credential")

        try await h.vault.importPasskeyRegistration(
            registrationID: "22222222-2222-4222-8222-222222222222",
            expectedAccountID: accountID,
            cipherID: nil,
            relyingPartyID: "new.example.test",
            userName: "new-user",
            userDisplayName: nil,
            userHandle: Data([5, 4, 3]),
            credentialID: newCredentialID,
            privateKeyPKCS8: pkcs8,
            creationDate: createdAt
        )
        r.expect(await h.api.createdRequests.count, createCount + 1,
                 "passkey import: server-id replay does not issue another create")
        r.expect(try await h.store.outbox(accountID: accountID).count, 0,
                 "passkey import: server-id replay does not enqueue another create")
    } catch {
        r.expectTrue(false, "passkey registration import threw: \(error)")
    }
}

/// Global cipher UUID lookups must still be scoped to the active account before any API
/// mutation. The fixture deliberately uses the same user key on two servers so decryption
/// alone could not accidentally mask the missing ownership check.
func checkCipherAccessIsAccountScoped(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do {
        h = try await Fixtures.makeHarness(tokenResults: [
            .success(Fixtures.tokenResponse(accessToken: "access-a")),
            .success(Fixtures.tokenResponse(accessToken: "access-b")),
        ])
    } catch { r.expectTrue(false, "account scope: makeHarness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    let item = PlaintextCipher(name: "Account A", login: .init(username: "alice"))
    let cipherID: String
    do {
        _ = try await h.auth.login(
            email: Fixtures.email,
            password: Fixtures.password,
            server: Fixtures.server
        )
        cipherID = try await h.vault.createCipher(item)
        let serverB = ServerEnvironment(string: "https://other.example.test")!
        _ = try await h.auth.login(
            email: Fixtures.email,
            password: Fixtures.password,
            server: serverB
        )
    } catch {
        r.expectTrue(false, "account scope setup threw: \(error)")
        return
    }

    await r.expectThrowsErrorAsync(
        RepositoryError.cipherNotFound,
        "account scope: read rejects another account's cipher"
    ) {
        _ = try await h.vault.cipher(id: cipherID)
    }
    await r.expectThrowsErrorAsync(
        RepositoryError.cipherNotFound,
        "account scope: update rejects another account's cipher before API"
    ) {
        try await h.vault.updateCipher(id: cipherID, item)
    }
    await r.expectThrowsErrorAsync(
        RepositoryError.cipherNotFound,
        "account scope: delete rejects another account's cipher before API"
    ) {
        try await h.vault.deleteCipher(id: cipherID)
    }

    r.expect(await h.api.updatedRequests.count, 0,
             "account scope: rejected update makes no API call")
    r.expect(await h.api.deletedIDs.count, 0,
             "account scope: rejected delete makes no API call")
    do {
        r.expect((try await h.store.cipher(
            id: cipherID,
            accountID: "https://vault.example.test|user@example.test"
        ))?.accountID,
                 "https://vault.example.test|user@example.test",
                 "account scope: rejected mutation preserves source row")
    } catch {
        r.expectTrue(false, "account scope verification threw: \(error)")
    }
}

func checkPasskeyImportsCoalesceWithPendingCreate(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())]) }
    catch { r.expectTrue(false, "passkey coalesce: harness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }
    do {
        _ = try await h.auth.login(
            email: Fixtures.email, password: Fixtures.password, server: Fixtures.server
        )
        let accountID = (await h.auth.session)!.accountID
        await h.api.setCreateError(NetworkingError.serverUnreachable)
        let localID = try await h.vault.createCipher(PlaintextCipher(
            name: "Offline login", login: .init(username: "alice")
        ))
        for index in 1...2 {
            try await h.vault.importPasskeyRegistration(
                registrationID: "00000000-0000-4000-8000-00000000000\(index)",
                expectedAccountID: accountID,
                cipherID: localID,
                relyingPartyID: "example.test",
                userName: "alice",
                userDisplayName: "Alice",
                userHandle: Data([UInt8(index)]),
                credentialID: Data([0xA0, UInt8(index)]),
                privateKeyPKCS8: Data([0x30, UInt8(index)]),
                creationDate: Date(timeIntervalSince1970: 1_700_000_000)
            )
        }
        let queued = try await h.store.outbox(accountID: accountID)
        r.expect(queued.count, 1,
                 "passkey coalesce: pending create and two imports share one row")
        r.expect(queued.first?.opType, "create",
                 "passkey coalesce: retained operation is create")
        r.expect(try await h.vault.cipher(id: localID).login?.fido2Credentials.count, 2,
                 "passkey coalesce: local row keeps both credentials")
        for index in 1...2 {
            r.expectTrue(try await h.store.isPasskeyImportCompleted(
                id: "00000000-0000-4000-8000-00000000000\(index)",
                accountID: accountID
            ), "passkey coalesce: receipt \(index) completed")
        }
    } catch {
        r.expectTrue(false, "passkey coalesce threw: \(error)")
    }
}

func checkPasskeyImportFallsBackWhenTargetDisappears(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())]) }
    catch { r.expectTrue(false, "passkey fallback: harness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }
    do {
        _ = try await h.auth.login(
            email: Fixtures.email, password: Fixtures.password, server: Fixtures.server
        )
        let accountID = (await h.auth.session)!.accountID
        try await h.vault.importPasskeyRegistration(
            registrationID: "99999999-9999-4999-8999-999999999999",
            expectedAccountID: accountID,
            cipherID: "deleted-target",
            relyingPartyID: "fallback.example",
            userName: "alice",
            userDisplayName: nil,
            userHandle: Data([1]),
            credentialID: Data([2]),
            privateKeyPKCS8: Data([3]),
            creationDate: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let fallbackID = "passkey-99999999-9999-4999-8999-999999999999"
        r.expect(try await h.vault.cipher(id: fallbackID).name, "fallback.example",
                 "passkey fallback: deterministic login preserves accepted credential")
        r.expect(try await h.store.outbox(accountID: accountID).first?.opType, "create",
                 "passkey fallback: queues a create instead of stale update")
    } catch {
        r.expectTrue(false, "passkey fallback threw: \(error)")
    }
}

func checkPasskeyImportFallsBackWhenTargetIsSoftDeleted(_ r: inout TestRunner) async {
    let h: Fixtures.Harness
    do { h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())]) }
    catch { r.expectTrue(false, "passkey stale target: harness threw: \(error)"); return }
    defer { Fixtures.cleanup(h.dir) }

    do {
        _ = try await h.auth.login(
            email: Fixtures.email, password: Fixtures.password, server: Fixtures.server
        )
        let accountID = (await h.auth.session)!.accountID
        let staleID = try await h.vault.createCipher(PlaintextCipher(
            name: "Target before deletion", login: .init(username: "alice")
        ))
        guard let row = try await h.store.cipher(id: staleID, accountID: accountID) else {
            r.expectTrue(false, "passkey stale target: original row exists"); return
        }
        try await h.store.upsertCiphers([CipherRow(
            id: row.id,
            accountID: row.accountID,
            type: row.type,
            folderID: row.folderID,
            organizationID: row.organizationID,
            favorite: row.favorite,
            reprompt: row.reprompt,
            edit: row.edit,
            viewPassword: row.viewPassword,
            revisionDate: row.revisionDate,
            creationDate: row.creationDate,
            deletedDate: "2026-07-17T00:00:00.000Z",
            encName: row.encName,
            encNotes: row.encNotes,
            encBlob: row.encBlob,
            encCipherKey: row.encCipherKey,
            searchText: row.searchText
        )])

        let registrationID = "88888888-8888-4888-8888-888888888888"
        try await h.vault.importPasskeyRegistration(
            registrationID: registrationID,
            expectedAccountID: accountID,
            cipherID: staleID,
            relyingPartyID: "stale-target.example",
            userName: "alice",
            userDisplayName: nil,
            userHandle: Data([1, 2]),
            credentialID: Data([3, 4]),
            privateKeyPKCS8: Data([5, 6]),
            creationDate: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let fallbackID = "passkey-\(registrationID)"
        r.expect(try await h.vault.cipher(id: fallbackID).name, "stale-target.example",
                 "passkey stale target: deterministic fallback login created")
        let queued = try await h.store.outbox(accountID: accountID)
        r.expect(queued.first { $0.entityID == fallbackID }?.opType, "create",
                 "passkey stale target: fallback queues create, never stale update")
        r.expect(try await h.vault.cipher(id: fallbackID)
            .login?.fido2Credentials.count, 1,
                 "passkey stale target: accepted credential is retained")
    } catch {
        r.expectTrue(false, "passkey stale target threw: \(error)")
    }
}
