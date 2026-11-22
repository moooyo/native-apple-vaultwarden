import Foundation
import UIShared
import VaultModels
import VaultRepository

func checkVaultTransferFormats(_ runner: inout TestRunner) async {
    let folder = PlaintextFolder(id: "source-folder", name: "Home")
    let password = " leading,\"quoted\"\r\n0123 "
    let login = PlaintextCipher(id: "original-id", name: "Example", folderID: folder.id,
                                favorite: true, reprompt: 1,
                                login: .init(username: "someone", password: password,
                                             uris: [.init(uri: "https://example.com", match: 3)],
                                             fido2Credentials: [.init(credentialId: "synthetic", counter: "0")]))
    let card = PlaintextCipher(type: CipherType.card.rawValue, name: "Card", card: .init(number: "0055"))
    let archive = VaultTransferArchive(folders: [folder], items: [login, card,
        PlaintextCipher(name: "Excluded organization", organizationID: "org"),
        PlaintextCipher(name: "Excluded deleted item", deletedDate: .now)])
    do {
        let json = try VaultTransferCodec.encodeJSON(archive)
        let decoded = try VaultTransferCodec.decodeJSON(json)
        runner.expect(decoded.items.count, 2, "transfer JSON: personal non-trash items only")
        runner.expectTrue(decoded.items.first?.login == login.login, "transfer JSON: login, passkeys and URI match preserved")
        runner.expect(decoded.items.last?.card?.number, "0055", "transfer JSON: card data and leading zeroes retained")
        runner.expectNil(decoded.items.first?.id, "transfer JSON: source item IDs never reused")
        runner.expect(decoded.folders, [folder], "transfer JSON: folder preserved")
        let vault = FakeVaultService(stored: [])
        let saved = try await VaultTransferWriter.persist(decoded, to: nil, existingFolders: [], vault: vault,
                                                         lease: .init(accountID: "test", generation: 0))
        runner.expect(saved, 2, "transfer writer: all items created")
        let imported = await vault.createdCiphers
        let destination = try await vault.folders().first
        runner.expect(imported.first?.folderID, destination?.id, "transfer writer: maps source folder ID to destination")
        runner.expectTrue(destination?.id != nil && destination?.id != folder.id, "transfer writer: source folder IDs never reused")

        let csv = try VaultTransferCodec.encodeCSV(archive)
        let decodedCSV = try VaultTransferCodec.decodeCSV(csv, source: .bitwarden)
        runner.expect(decodedCSV.items.count, 1, "transfer CSV: only personal logins and notes")
        runner.expectTrue(decodedCSV.items.first?.login?.password == password, "transfer CSV: preserves quotes, CRLF and significant spaces")
        let apple = Data("\u{FEFF}Title,URL,Username,Password,Notes,OTPAuth\r\nExample,https://example.com,me,0123,Text,otpauth://totp/demo\r\n".utf8)
        let appleLogin = try VaultTransferCodec.decodeCSV(apple, source: .apple).items.first?.login
        runner.expect(appleLogin?.totp, "otpauth://totp/demo", "transfer Apple CSV: reads OTPAuth")
        runner.expect(appleLogin?.password, "0123", "transfer Apple CSV: never coerces fields to numbers")
    } catch { runner.expectTrue(false, "transfer: supported files should round trip") }

    for file in [#"{"encrypted":false,"items":[{"name":"Unknown","type":46}]}"#,
                 #"{"items":[{"name":"Personal","type":1,"folderId":"missing"}]}"#,
                 #"{"items":[{"name":"Org","type":1,"organizationId":"foreign"}]}"#,
                 #"{"items":[{"name":"History","type":1,"passwordHistory":[{"password":"old"}]}]}"#,
                 #"{"items":[{"name":"Wrong payload","type":3,"login":{"password":"secret"}}]}"#,
                 #"{"items":[{"name":"Mixed payloads","type":1,"login":{},"sshKey":{}}]}"#,
                 #"{"items":[{"name":"Missing payload","type":2}]}"#] {
        do {
            _ = try VaultTransferCodec.decodeJSON(Data(file.utf8))
            runner.expectTrue(false, "transfer JSON: reject unsupported content before mutation")
        } catch { runner.expectTrue(true, "transfer JSON: unsupported content rejected") }
    }
    do {
        _ = try VaultTransferCodec.decodeCSV(Data("name,url,username,password\nExample,url,me,\"unclosed".utf8), source: .browser)
        runner.expectTrue(false, "transfer CSV: rejects unterminated quoted fields")
    } catch { runner.expectTrue(true, "transfer CSV: malformed file rejected") }

    for restricted in [
        PlaintextCipher(name: "Field with separators", login: .init(), fields: [.init(type: 0, name: "section: entry", value: "value")]),
        PlaintextCipher(name: "Multiline field", login: .init(), fields: [.init(type: 0, name: "section", value: "line one\r\nline two")]),
        PlaintextCipher(name: "URI with separator", login: .init(uris: [.init(uri: "https://example.com/a,b")]))
    ] {
        let restrictedArchive = VaultTransferArchive(folders: [], items: [restricted])
        do {
            _ = try VaultTransferCodec.encodeCSV(restrictedArchive)
            runner.expectTrue(false, "transfer CSV: reject content that would be lost or misread on restore")
        } catch let error as VaultTransferError {
            runner.expect(error, .unrepresentableCSV, "transfer CSV: rejection can offer JSON instead")
        } catch { runner.expectTrue(false, "transfer CSV: unexpected export error") }
        do {
            let restored = try VaultTransferCodec.decodeJSON(VaultTransferCodec.encodeJSON(restrictedArchive)).items.first
            runner.expect(restored?.fields, restricted.fields, "transfer JSON: lossless alternative preserves custom fields")
            runner.expect(restored?.login, restricted.login, "transfer JSON: lossless alternative preserves URIs")
        } catch { runner.expectTrue(false, "transfer JSON: lossless alternative should round trip") }
    }
    do {
        _ = try VaultTransferCodec.encodeCSV(.init(folders: [folder], items: [card]))
        runner.expectTrue(false, "transfer CSV: cannot export a header with no restorable items")
    } catch let error as VaultTransferError {
        runner.expect(error, .emptyExport, "transfer CSV: an empty projection has a distinct error")
    } catch { runner.expectTrue(false, "transfer CSV: unexpected empty export error") }
    do {
        _ = try VaultTransferCodec.encodeJSON(.init(folders: [], items: [login]))
        runner.expectTrue(false, "transfer JSON: cannot export a reference to a missing folder")
    } catch let error as VaultTransferError {
        runner.expect(error, .invalidFile, "transfer JSON: an inconsistent backup is rejected before writing")
    } catch { runner.expectTrue(false, "transfer JSON: unexpected inconsistent export error") }

    let invalid = VaultTransferArchive(folders: [folder], items: [login,
        .init(type: CipherType.card.rawValue, name: "Mismatch", login: .init(password: "do-not-drop"))])
    let untouched = FakeVaultService(stored: [])
    do {
        _ = try await VaultTransferWriter.persist(invalid, to: nil, existingFolders: [], vault: untouched,
                                                 lease: .init(accountID: "test", generation: 0))
        runner.expectTrue(false, "transfer writer: malformed batch must fail before writes")
    } catch {
        let folders = try? await untouched.folders()
        let saved = await untouched.createdCiphers
        runner.expect(folders?.count, 0, "transfer writer: validation precedes folder creation")
        runner.expect(saved.count, 0, "transfer writer: cannot partially import an invalid archive")
    }

    await checkSSHKeyTransfer(&runner)
}

private func checkSSHKeyTransfer(_ runner: inout TestRunner) async {
    let folder = PlaintextFolder(id: "ssh-folder", name: "Keys")
    let note = PlaintextCipher(type: CipherType.secureNote.rawValue, name: "Note", folderID: folder.id, secureNote: .init())
    let complete = PlaintextCipher(type: CipherType.sshKey.rawValue, name: "Key", folderID: folder.id,
                                   sshKey: .init(privateKey: "\nfixture-private-key\n", publicKey: "fixture-public-key",
                                                 keyFingerprint: "fixture-fingerprint"))
    let lease = AccountSessionLease(accountID: "test", generation: 0)
    var incomplete = complete
    incomplete.sshKey?.privateKey = " \n\t "
    let incompleteArchive = VaultTransferArchive(folders: [folder], items: [note, incomplete])
    let vault = FakeVaultService()
    do {
        let decoded = try VaultTransferCodec.decodeJSON(VaultTransferCodec.encodeJSON(incompleteArchive))
        runner.expect(decoded.items.last?.sshKey, incomplete.sshKey, "transfer JSON: preserves recoverable fields of an incomplete SSH key")
        do {
            _ = try await VaultTransferWriter.persist(decoded, to: nil, existingFolders: [], vault: vault, lease: lease)
            runner.expectTrue(false, "transfer writer: reject an incomplete SSH key before writing")
        } catch {
            runner.expect(error as? RepositoryError, .incompleteSSHKey, "transfer writer: identifies incomplete SSH data")
        }
        runner.expect(try await vault.folders(), [], "transfer writer: incomplete SSH data cannot create folders")
        runner.expect(await vault.createdCiphers.count, 0, "transfer writer: incomplete SSH data blocks preceding valid items")

        let archive = VaultTransferArchive(folders: [folder], items: [note, complete])
        let saved = try await VaultTransferWriter.persist(archive, to: nil, existingFolders: [], vault: vault, lease: lease)
        runner.expect(saved, 2, "transfer writer: complete SSH data may be imported")
        runner.expect(await vault.createdCiphers.last?.sshKey, complete.sshKey, "transfer writer: SSH validation preserves key text")
    } catch { runner.expectTrue(false, "transfer: SSH checks should preserve export and accept complete imports") }
}
