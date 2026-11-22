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

        let csv = VaultTransferCodec.encodeCSV(archive)
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
}
