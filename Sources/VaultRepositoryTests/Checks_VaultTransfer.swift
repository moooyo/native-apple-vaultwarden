import CryptoCore
import Foundation
import Networking
import UIShared
import VaultModels
import VaultRepository
import VaultStore

func checkVaultTransferAuthorization(_ runner: inout TestRunner) async {
    do {
        let harness = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())])
        defer { Fixtures.cleanup(harness.dir) }
        _ = try await harness.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        guard let lease = await harness.auth.currentSessionLease() else {
            runner.expectTrue(false, "transfer: authenticated session required"); return
        }
        try await harness.auth.verifyMasterPassword(Fixtures.password, for: lease)
        do {
            try await harness.auth.verifyMasterPassword("not-the-password", for: lease)
            runner.expectTrue(false, "transfer: wrong master password rejected even while unlocked")
        } catch RepositoryError.authenticationFailed { runner.expectTrue(true, "transfer: rejected wrong password") }
        let malformed = CipherRow(id: "damaged", accountID: lease.accountID, type: 1,
                                  revisionDate: Fixtures.iso(.now), creationDate: Fixtures.iso(.now),
                                  encName: Fixtures.enc("Item"), encBlob: #"{"login":{"password":"damaged"}}"#)
        try await harness.store.upsertCiphers([malformed])
        do {
            _ = try await harness.vault.exportSnapshot(expectedSession: lease)
            runner.expectTrue(false, "transfer: damaged password must not silently export as empty")
        } catch { runner.expectTrue(true, "transfer: abort export on field decryption failure") }
        await harness.auth.lock()
        do {
            try await harness.auth.verifyMasterPassword(Fixtures.password, for: lease)
            runner.expectTrue(false, "transfer: a stale operation must not re-unlock the vault")
        } catch { runner.expectTrue(true, "transfer: lock revokes export") }
        let stillLocked = await harness.auth.isUnlocked() == false
        runner.expectTrue(stillLocked, "transfer: reauthentication never installs a key")
    } catch { runner.expectTrue(false, "transfer: authorization fixture failed") }
    await checkVaultTransferFileRoundTrips(&runner)
}

private func checkVaultTransferFileRoundTrips(_ runner: inout TestRunner) async {
    do {
        let source = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())])
        defer { Fixtures.cleanup(source.dir) }
        let destinationEmail = "restore@example.test"
        let destinationPassword = "restore fixture account"
        let masterKey = try KDF.deriveMasterKey(password: destinationPassword, email: destinationEmail,
                                                iterations: Fixtures.iterations)
        let userKey = Data(repeating: 42, count: 64)
        let protectedKey = try SymmetricCrypto.encrypt(userKey, using: KeyStretch.stretchMasterKey(masterKey))
        let destinationToken = TokenResponse(accessToken: "restore-bearer", expiresIn: 3600, refreshToken: nil,
                                             tokenType: "Bearer", key: protectedKey, privateKey: nil, kdf: 0,
                                             kdfIterations: Fixtures.iterations, twoFactorToken: nil)
        let destination = try await Fixtures.makeHarness(tokenResults: [.success(destinationToken)])
        defer { Fixtures.cleanup(destination.dir) }
        _ = try await source.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        _ = try await destination.auth.login(email: destinationEmail, password: destinationPassword, server: Fixtures.server)
        let sourceAuth = AuthServiceAdapter(repository: source.auth)
        let destinationAuth = AuthServiceAdapter(repository: destination.auth)
        let sourceVault = VaultServiceAdapter(repository: source.vault)
        let destinationVault = VaultServiceAdapter(repository: destination.vault)
        guard let sourceLease = await sourceAuth.transferSession(), let destinationLease = await destinationAuth.transferSession(),
              sourceLease.accountID != destinationLease.accountID else {
            runner.expectTrue(false, "transfer files: independent source and destination sessions required")
            return
        }
        let folder = try await source.vault.createFolder(name: "Projects")
        let existingFolder = try await destination.vault.createFolder(name: "Projects")
        let csvFolder = try await destination.vault.createFolder(name: "CSV restore")
        let plainFolder = try await destination.vault.createFolder(name: "Plain JSON restore")
        let malformedArchive = Data(#"{"folders":[{"id":"folder","name":"Do not create"}],"items":[{"name":"Valid","type":1,"login":{}},{"name":"Broken","type":1,"folderId":"missing","login":{}}]}"#.utf8)
        await runner.expectThrowsErrorAsync(VaultTransferError.invalidFile, "transfer files: invalid references abort the whole restore") {
            let invalid = try await VaultTransferFiles.decode(malformedArchive, format: .bitwardenJSON)
            _ = try await VaultTransferWriter.persist(invalid, to: nil, existingFolders: [],
                                                      vault: destinationVault, lease: destinationLease)
        }
        runner.expect(await destination.api.createdRequests.count, 0, "transfer files: malformed input writes no ciphers")
        runner.expect(try await destination.vault.folders().count, 3, "transfer files: malformed input writes no folders")
        let login = PlaintextCipher(name: "Login", folderID: folder, favorite: true, reprompt: 1,
            login: .init(username: "fixture-user", password: " leading,\"quoted\"\r\n0123 ",
                         totp: "otpauth://totp/fixture?secret=TESTBACKUP",
                         uris: [.init(uri: "https://login.example.test/path?q=one", match: 3)],
                         fido2Credentials: [.init(credentialId: "fixture-passkey", keyValue: "fixture-key-data", counter: "0")]),
            fields: [.init(type: FieldType.hidden.rawValue, name: "Label", value: " label: value ")])
        let note = PlaintextCipher(type: CipherType.secureNote.rawValue, name: "Archived note", notes: "line 1\r\nline 2",
                                   folderID: folder, secureNote: .init())
        let card = PlaintextCipher(type: CipherType.card.rawValue, name: "Card", card: .init(number: "00051", expMonth: "05"))
        let identity = PlaintextCipher(type: CipherType.identity.rawValue, name: "Identity", identity: .init(firstName: "Fixture", postalCode: "00100"))
        let ssh = PlaintextCipher(type: CipherType.sshKey.rawValue, name: "SSH", sshKey: .init(privateKey: "fixture-private-key"))
        let items = [login, note, card, identity, ssh]
        for item in items {
            let id = try await source.vault.createCipher(item)
            if item.name == note.name {
                try await source.store.setCipherVisibility(id: id, accountID: sourceLease.accountID, deletedDate: nil,
                                                           archivedDate: Fixtures.iso(.now))
            }
        }
        let trash = try await source.vault.createCipher(.init(name: "Excluded trash", login: .init(password: "excluded")))
        try await source.vault.changeCipherVisibility(id: trash, change: .trash)
        let date = Fixtures.iso(.now)
        try await source.store.upsertCiphers([.init(id: "org-row", accountID: sourceLease.accountID, type: CipherType.login.rawValue,
                                                    organizationID: "fixture-org", revisionDate: date, creationDate: date)])

        let filePassword = " separate export password "
        for (format, importFormat, filename): (VaultTransferExportFormat, VaultTransferImportFormat, String) in [
            (.encryptedJSON, .bitwardenJSON, "protected.json"),
            (.json, .bitwardenJSON, "plain.json"),
            (.csv, .csv(.bitwarden), "portable.csv")
        ] {
            let output = try await VaultTransferFiles.prepareExport(format: format, filePassword: filePassword,
                masterPassword: Fixtures.password, auth: sourceAuth, vault: sourceVault, lease: sourceLease)
            let file = source.dir.appendingPathComponent(filename)
            try output.write(to: file, options: .atomic)
            let diskBytes = try await VaultTransferFiles.read(file)
            let encrypted = filename == "protected.json"
            if filename != "portable.csv" {
                runner.expect(try await VaultTransferFiles.isEncrypted(diskBytes), encrypted,
                              "transfer files: detect the protected JSON envelope")
            }
            if encrypted {
                runner.expectTrue(!String(decoding: diskBytes, as: UTF8.self).contains("fixture-private-key"),
                                  "transfer files: protected backup does not expose fixture secrets")
                await runner.expectThrowsErrorAsync(PasswordProtectedExportError.authenticationFailed,
                                                    "transfer files: wrong file password rejects the whole archive") {
                    let invalid = try await VaultTransferFiles.decode(diskBytes, format: importFormat, password: "wrong-file-password")
                    _ = try await VaultTransferWriter.persist(invalid, to: nil, existingFolders: [],
                                                              vault: destinationVault, lease: destinationLease)
                }
                runner.expect(await destination.api.createdRequests.count, 0, "transfer files: wrong password writes no ciphers")
                runner.expect(try await destination.vault.folders().count, 3, "transfer files: wrong password writes no folders")
            }
            let archive = try await VaultTransferFiles.decode(diskBytes, format: importFormat, password: filePassword)
            let isCSV = filename == "portable.csv"
            runner.expect(Set(archive.items.map(\.name)), Set((isCSV ? [login, note] : items).map(\.name)),
                          "transfer files: \(filename) includes only the supported personal items")
            let selectedFolder = isCSV ? csvFolder : plainFolder
            let folderForRestore = encrypted ? nil : selectedFolder
            let destinationFolders = try await destination.vault.folders()
            let previousItems = try await destination.vault.ciphers()
            let count = try await VaultTransferWriter.persist(archive, to: folderForRestore,
                existingFolders: destinationFolders, vault: destinationVault, lease: destinationLease)
            runner.expect(count, isCSV ? 2 : items.count, "transfer files: \(filename) restores into the independent account")
            let previousIDs = Set(previousItems.compactMap(\.id))
            let restored = try await destination.vault.ciphers().filter { $0.id.map(previousIDs.contains) == false }
            runner.expect(restored.count, count, "transfer files: \(filename) restored items decrypt under the destination key")
            let expectedFolder = folderForRestore ?? existingFolder
            let restoredLogin = restored.first { $0.name == login.name && $0.folderID == expectedFolder }
            let restoredNote = restored.first { $0.name == note.name && $0.folderID == expectedFolder }
            runner.expect(restoredLogin?.login?.password, login.login?.password, "transfer files: significant password whitespace survives \(filename)")
            runner.expect(restoredNote?.notes, note.notes, "transfer files: archived note restored with multiline content")
            runner.expect(try await destination.vault.folders().count, 3, "transfer files: existing named folders are reused")
            if isCSV {
                runner.expect(restoredLogin?.fields, [.init(type: FieldType.text.rawValue, name: "Label", value: " label: value ")],
                              "transfer files: CSV keeps field values but not field types")
            } else {
                runner.expect(restoredLogin?.login, login.login, "transfer files: \(filename) retains URI matching, TOTP and passkeys")
                runner.expect(restoredLogin?.fields, login.fields, "transfer files: \(filename) retains custom field types")
                runner.expect(restored.first { $0.name == card.name }?.card, card.card, "transfer files: card round-trips")
                runner.expect(restored.first { $0.name == identity.name }?.identity, identity.identity, "transfer files: identity round-trips")
                runner.expect(restored.first { $0.name == ssh.name }?.sshKey, ssh.sshKey, "transfer files: SSH key round-trips")
            }
        }
    } catch { runner.expectTrue(false, "transfer file round-trip fixture failed: \(error)") }
}

func checkVaultTransferIdentityBatching(_ runner: inout TestRunner) async {
    do {
        let identities = FakeIdentityStore(enabled: true)
        let harness = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())], identityStore: identities)
        defer { Fixtures.cleanup(harness.dir) }
        _ = try await harness.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        guard let lease = await harness.auth.currentSessionLease() else {
            runner.expectTrue(false, "batch import: session required"); return
        }
        let items = (1...3).map { index in
            PlaintextCipher(name: "Login \(index)", login: .init(username: "user", password: "secret",
                                                               uris: [.init(uri: "https://site\(index).example")]))
        }
        let baseline = await identities.replaceAllCalls
        try await harness.vault.importCiphers(items, expectedSession: lease)
        runner.expect(await identities.replaceAllCalls, baseline + 1, "batch import: three creates rebuild identities once")
        let requests = await harness.api.createdRequests.count
        await harness.api.failCreate(onCall: requests + 2)
        do {
            try await harness.vault.importCiphers(items, expectedSession: lease)
            runner.expectTrue(false, "batch import: partial server rejection reported")
        } catch let partial as PartialCipherImport {
            runner.expect(partial.savedCount, 1, "batch import: exact committed prefix on server failure")
        }
        runner.expect(await identities.replaceAllCalls, baseline + 2, "batch import: partial failure rebuilds once")
        await harness.api.pauseNextCreate()
        let operation = Task { try await harness.vault.importCiphers(items, expectedSession: lease) }
        await harness.api.waitUntilCreateIsPaused()
        operation.cancel()
        await harness.api.resumePausedCreate()
        do {
            try await operation.value
            runner.expectTrue(false, "batch import: cancellation reported")
        } catch let partial as PartialCipherImport {
            runner.expect(partial.savedCount, 1, "batch import: cancellation does not recreate acknowledged items")
        }
        runner.expect(await identities.replaceAllCalls, baseline + 3, "batch import: cancelled batch rebuilds once")
        await harness.api.setCreateError(NetworkingError.serverUnreachable)
        try await harness.vault.importCiphers(items, expectedSession: lease)
        runner.expect(await identities.replaceAllCalls, baseline + 4, "batch import: offline creates rebuild once")
        let outbox = try await harness.store.outboxForFlush(accountID: lease.accountID)
        runner.expect(outbox.count, 3, "batch import: all offline items retained in the account outbox")
    } catch { runner.expectTrue(false, "batch import: unexpected error") }
}
