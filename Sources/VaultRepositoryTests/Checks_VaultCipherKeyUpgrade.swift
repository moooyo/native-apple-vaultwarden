import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import Networking
import SyncEngine
import VaultRepository

func checkLegacyCipherKeyUpgrade(_ r: inout TestRunner) async {
    await checkLegacyCipherKeyUpgradePreservesFields(&r)
    await checkLegacyCipherKeyUpgradeDoesNotReplay(&r)
    await checkLegacyCipherKeyUpgradeRechecksSession(&r)
    await checkLegacyCipherKeyUpgradeStopsOnAccountChange(&r)
}

private let originalRevision = "2026-01-01T00:00:00.123456Z"
private let passkeyCreation = "2025-01-01T00:00:00.234567Z"
private let passwordRevision = "2025-02-01T00:00:00.345678Z"
private let upgradeNotes = "\u{FEFF}  notes\n \u{65}\u{301} "

private func upgradeTestID(_ number: Int) -> String {
    "1581f49d-a15b-4490-a70f-\(String(format: "%012d", number))"
}

private func upgradeWireCipher(_ number: Int, _ changes: [String: Any] = [:]) -> [String: Any] {
    let uri = Fixtures.enc("https://example.test/login")
    let fields: [[String: Any]] = [
        ["Type": 1, "Name": Fixtures.enc("Hidden"), "Value": Fixtures.enc("  hidden  ")],
        ["Type": 3, "Name": Fixtures.enc("Linked"), "LinkedId": 100],
    ]
    let login: [String: Any] = [
        "Username": Fixtures.enc("alice"), "Password": Fixtures.enc("password"), "Totp": Fixtures.enc("otp"),
        "PasswordRevisionDate": passwordRevision, "AutoFillOnPageLoad": NSNull(),
        "Uri": uri, "Uris": [["Uri": uri, "Match": 3, "UriChecksum": NSNull()]],
        "Fido2Credentials": [["CredentialId": Fixtures.enc("b64.AQIDBA"), "KeyValue": Fixtures.enc("passkey"),
                              "RpId": Fixtures.enc("example.test"), "Counter": Fixtures.enc("8"),
                              "CreationDate": passkeyCreation]],
    ]
    let name = Fixtures.enc("Legacy Login")
    let notes = Fixtures.enc(upgradeNotes)
    let original: [String: Any] = [
        "Id": upgradeTestID(number), "Type": 1, "Name": name, "Notes": notes,
        "Favorite": true, "Reprompt": 1, "Edit": true, "ViewPassword": true,
        "Object": "cipherDetails", "OrganizationUseTotp": true, "FolderId": upgradeTestID(100),
        "Login": login, "Fields": fields, "PasswordHistory": [],
        "Data": login.merging(["Name": name, "Notes": notes, "Fields": fields]) { current, _ in current },
        "RevisionDate": originalRevision, "CreationDate": "2025-01-01T00:00:00.000Z",
    ]
    return original.merging(changes) { _, new in new }
}

private func upgradeSyncResponse(_ ciphers: [[String: Any]], accountKey: EncString? = nil) throws -> SyncResponse {
    var profile: [String: Any] = ["Id": "profile-1", "Email": Fixtures.email, "Organizations": []]
    if let accountKey { profile["Key"] = accountKey.stringValue }
    let data = try JSONSerialization.data(withJSONObject: ["Profile": profile, "Folders": [], "Ciphers": ciphers])
    return try VaultJSON.decoder().decode(SyncResponse.self, from: data)
}

private func checkLegacyCipherKeyUpgradePreservesFields(_ r: inout TestRunner) async {
    do {
        let original = upgradeWireCipher(1)
        guard let source = try upgradeSyncResponse([original]).ciphers.first else {
            r.expectTrue(false, "key upgrade: source fixture failed to decode"); return
        }
        let server = ConflictTestServer(cipher: source)
        let h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())], cipherServer: server)
        defer { Fixtures.cleanup(h.dir) }
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        guard let lease = await h.auth.currentSessionLease() else {
            r.expectTrue(false, "key upgrade: missing account session"); return
        }
        let pending = OutboxRow(accountID: lease.accountID, opType: OutboxOp.update.rawValue,
                                entityType: OutboxEntity.cipher.rawValue, entityID: upgradeTestID(2), payloadJSON: "{}")
        _ = try await h.store.enqueueOutbox(pending)
        let invalidUTF8 = try SymmetricCrypto.encrypt(Data([0xff]), using: Fixtures.userKey()).stringValue
        let skipped: [[String: Any]] = [
            upgradeWireCipher(2),
            upgradeWireCipher(3, ["Type": 99]),
            upgradeWireCipher(4, ["PasswordHistory": [["Password": Fixtures.enc("old")]]]),
            upgradeWireCipher(5, ["ArchivedDate": originalRevision]),
            upgradeWireCipher(6, ["DeletedDate": originalRevision]),
            upgradeWireCipher(7, ["Attachments": [["Id": "attachment", "Key": Fixtures.enc("attachment-key")]]]),
            upgradeWireCipher(8, ["Notes": invalidUTF8, "Data": NSNull()]),
            upgradeWireCipher(9, ["Login": ["FutureField": Fixtures.enc("unmodeled")], "Data": NSNull()]),
            upgradeWireCipher(10, ["Notes": "not an EncString"]),
            upgradeWireCipher(11, ["Login": ["Uris": [["Match": 3]]], "Data": NSNull()]),
            upgradeWireCipher(12, ["Login": ["Uris": [["Uri": Fixtures.enc("url"), "UriChecksum": Fixtures.enc("checksum")]]],
                                   "Data": NSNull()]),
            upgradeWireCipher(13, ["Data": ["Notes": Fixtures.enc("not a mirror")]]),
            upgradeWireCipher(14),
            ["Id": upgradeTestID(14), "Name": "malformed duplicate id"],
            upgradeWireCipher(15, ["UnrecognizedEnvelopeField": NSNull()]),
        ]
        let notLegacyPersonal = [
            upgradeWireCipher(16, ["Key": Fixtures.protectedCipherKey().stringValue]),
            upgradeWireCipher(17, ["OrganizationId": upgradeTestID(101)]),
        ]
        await h.api.setSyncResponse(try upgradeSyncResponse([original] + skipped + notLegacyPersonal))
        let result = try await h.vault.upgradeLegacyCipherKeys(expectedSession: lease)
        r.expect(result.upgraded, 1, "key upgrade: migrate only the proven lossless item")
        r.expect(result.skipped, skipped.count, "key upgrade: malformed, pending or unsupported items are left alone")
        r.expect(result.failed, 0, "key upgrade: no attempted write failed")
        r.expectTrue(!result.requiresSync, "key upgrade: server acknowledged the write")
        r.expect(try await h.store.outbox(accountID: lease.accountID).map(\.entityID), [pending.entityID],
                 "key upgrade: an unrelated outbox operation is neither sent nor changed")

        let requests = await h.api.updatedRequests
        r.expect(requests.map(\.id), [source.id], "key upgrade: updates the original server ID only")
        guard let request = requests.first?.req, let wrapped = request.key,
              let password = request.login?.password, let notes = request.notes else {
            r.expectTrue(false, "key upgrade: request carries the wrapped item key and protected fields"); return
        }
        let keyBytes = try await h.keyVault.decrypt(wrapped)
        let key = try SymmetricCryptoKey(combined: keyBytes)
        r.expect(keyBytes.count, 64, "key upgrade: wrapped under the account key")
        r.expect(try SymmetricCrypto.decrypt(password, using: key), Data("password".utf8),
                 "key upgrade: login password uses the item key")
        r.expect(try SymmetricCrypto.decrypt(notes, using: key), Data(upgradeNotes.utf8),
                 "key upgrade: whitespace and the exact UTF-8 bytes survive")
        r.expect(request.lastKnownRevisionDate, source.revisionDate, "key upgrade: uses original server revision")
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let wire = try JSONSerialization.jsonObject(with: encoder.encode(request)) as? [String: Any]
        let loginWire = wire?["login"] as? [String: Any]
        let credentials = loginWire?["fido2Credentials"] as? [[String: Any]]
        r.expect(wire?["lastKnownRevisionDate"] as? String, originalRevision, "key upgrade: revision retains exact wire precision")
        r.expect(loginWire?["passwordRevisionDate"] as? String, passwordRevision, "key upgrade: retains exact password revision")
        r.expect(credentials?.first?["creationDate"] as? String, passkeyCreation, "key upgrade: retains exact passkey creation date")

        let cipher = try await h.vault.cipher(id: source.id)
        r.expect(cipher.protectedCipherKey, wrapped, "key upgrade: only confirmed key is persisted")
        r.expect(cipher.creationDate, source.creationDate, "key upgrade: preserves server creation metadata")
        r.expect(cipher.revisionDate, source.revisionDate.addingTimeInterval(60), "key upgrade: caches the server's confirmed revision")
        r.expect(cipher.folderID, source.folderId, "key upgrade: keeps folder")
        r.expect(cipher.favorite, source.favorite, "key upgrade: keeps favorite flag")
        r.expect(cipher.reprompt, source.reprompt, "key upgrade: keeps reprompt setting")
        r.expect(cipher.login?.uris, [.init(uri: "https://example.test/login", match: 3)], "key upgrade: keeps URI match")
        r.expect(cipher.login?.fido2Credentials.first?.keyValue, "passkey", "key upgrade: keeps passkey private material")
        r.expect(cipher.fields.map(\.type), [1, 3], "key upgrade: keeps hidden and linked field kinds")
        r.expect(cipher.fields.first?.value, "  hidden  ", "key upgrade: keeps hidden custom field bytes")
        r.expect(cipher.fields.last?.linkedId, 100, "key upgrade: keeps linked field metadata")
    } catch { r.expectTrue(false, "key upgrade preservation threw: \(error)") }
}

private func checkLegacyCipherKeyUpgradeDoesNotReplay(_ r: inout TestRunner) async {
    do {
        let h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())])
        defer { Fixtures.cleanup(h.dir) }
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        guard let lease = await h.auth.currentSessionLease() else {
            r.expectTrue(false, "key upgrade uncertain write: missing account session"); return
        }
        let original = upgradeWireCipher(23)
        await h.api.setSyncResponse(try upgradeSyncResponse([original, upgradeWireCipher(24)]))
        await h.api.setUpdateError(NetworkingError.transport("Fixture lost the PUT response"))
        let result = try await h.vault.upgradeLegacyCipherKeys(expectedSession: lease)
        r.expect(result.upgraded, 0, "key upgrade uncertain write: does not claim success")
        r.expect(result.failed, 1, "key upgrade uncertain write: only one ambiguous item is attempted")
        r.expectTrue(result.requiresSync, "key upgrade uncertain write: requires a fresh read before a retry")
        r.expect(try await h.store.outbox(accountID: lease.accountID).count, 0, "key upgrade uncertain write: no replay in outbox")
        r.expect(try await h.store.allCiphers(accountID: lease.accountID).count, 0,
                 "key upgrade uncertain write: no optimistic local state is persisted")
        let calls = await h.api.updatedRequests
        r.expect(calls.count, 1, "key upgrade uncertain write: the batch stops before sending another PUT")
        guard let request = calls.first?.req, let key = request.key else {
            r.expectTrue(false, "key upgrade uncertain write: request had a wrapped key"); return
        }
        let accepted = FakeAPI.echo(request, id: upgradeTestID(23))
        await h.api.setUpdateError(nil)
        await h.api.setSyncResponse(try Fixtures.syncResponse(ciphers: [accepted]))
        let retry = try await h.vault.upgradeLegacyCipherKeys(expectedSession: lease)
        r.expect(retry.upgraded, 0, "key upgrade uncertain write: a fresh snapshot already includes the item's key")
        r.expect(await h.api.updatedRequests.count, 1, "key upgrade uncertain write: manual retry sends no second PUT")
        r.expect(accepted.key, key, "key upgrade uncertain write: server retained the first request's key")
    } catch { r.expectTrue(false, "key upgrade uncertain write threw: \(error)") }
}

private func checkLegacyCipherKeyUpgradeRechecksSession(_ r: inout TestRunner) async {
    do {
        let h = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())])
        defer { Fixtures.cleanup(h.dir) }
        _ = try await h.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        guard let lease = await h.auth.currentSessionLease() else {
            r.expectTrue(false, "key upgrade session: missing account session"); return
        }
        await h.api.setSyncResponse(try upgradeSyncResponse([upgradeWireCipher(25)]))
        await h.api.pauseNextSync()
        let task = Task { try await h.vault.upgradeLegacyCipherKeys(expectedSession: lease) }
        await h.api.waitUntilSyncIsPaused()
        await h.vault.lock()
        await h.api.resumePausedSync()
        await r.expectThrowsAsync("key upgrade session: lock invalidates the active batch") {
            _ = try await task.value
        }
        r.expect(await h.api.updatedRequests.count, 0, "key upgrade session: no PUT after a lock during the initial read")
    } catch { r.expectTrue(false, "key upgrade session setup threw: \(error)") }
}

private func checkLegacyCipherKeyUpgradeStopsOnAccountChange(_ r: inout TestRunner) async {
    do {
        let harness = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())])
        defer { Fixtures.cleanup(harness.dir) }
        _ = try await harness.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        guard let lease = await harness.auth.currentSessionLease() else {
            r.expectTrue(false, "Key upgrade rotation fixture has an active session")
            return
        }
        let pending = OutboxRow(accountID: lease.accountID, opType: OutboxOp.update.rawValue,
                                entityType: OutboxEntity.cipher.rawValue, entityID: upgradeTestID(2), payloadJSON: "{}")
        _ = try await harness.store.enqueueOutbox(pending)
        let newKey = try SymmetricCrypto.encrypt(Fixtures.cipherKeyData(), using: Fixtures.stretchedMasterKey())
        await harness.api.setSyncResponse(try upgradeSyncResponse([upgradeWireCipher(1)], accountKey: newKey))

        await r.expectThrowsErrorAsync(RepositoryError.reauthenticationRequired, "Key upgrade stops on changed account unlock material") {
            _ = try await harness.vault.upgradeLegacyCipherKeys(expectedSession: lease)
        }
        r.expectTrue(await harness.auth.requiresNewLogin(), "A changed account key requires sign-in")
        r.expectTrue(!(await harness.auth.isUnlocked()), "A changed account key revokes unlocked access")
        r.expectTrue(await harness.api.updatedRequests.isEmpty, "Key upgrade never sends a write under the old key")
        r.expect(try await harness.store.outbox(accountID: lease.accountID).map(\.entityID), [pending.entityID],
                 "Revoking a stale session leaves pending edits on the device")
    } catch { r.expectTrue(false, "Key upgrade account-change fixture threw: \(error)") }
}
