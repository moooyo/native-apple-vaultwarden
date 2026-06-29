import Foundation
import VaultModels
import CryptoCore

func checkCipher(_ r: inout TestRunner) {
    let decoder = VaultJSON.decoder()

    // Login cipher — camelCase
    do {
        let c = try decoder.decode(CipherResponse.self, from: TestJSON.cipherLoginCamel().data(using: .utf8)!)
        r.expect(c.id, "cipher-1", "cipher camel id")
        r.expect(c.type, .login, "cipher camel type == login")
        r.expect(c.folderId, "folder-9", "cipher camel folderId")
        r.expectTrue(c.organizationId == nil, "cipher camel organizationId nil")
        r.expect(c.favorite, true, "cipher camel favorite")
        r.expect(c.reprompt, 0, "cipher camel reprompt")
        r.expect(c.edit, true, "cipher camel edit")
        r.expect(c.viewPassword, true, "cipher camel viewPassword")
        // name is a (non-optional) EncString — proven by successful decode + type
        r.expect(c.name.type, .aesCbc256_HmacSha256_B64, "cipher camel name is EncString")
        r.expectTrue(c.notes != nil, "cipher camel notes is EncString?")
        r.expectTrue(c.key != nil, "cipher camel key is EncString?")
        // revisionDate is a Date
        r.expectTrue(c.revisionDate.timeIntervalSince1970 > 0, "cipher camel revisionDate is Date")
        r.expectTrue(c.creationDate != nil, "cipher camel creationDate present")
        r.expectTrue(c.deletedDate == nil, "cipher camel deletedDate nil")

        // login sub-object
        guard let login = c.login else {
            r.expectTrue(false, "cipher camel login present"); return
        }
        r.expectTrue(login.username != nil, "cipher camel login.username EncString?")
        r.expectTrue(login.password != nil, "cipher camel login.password EncString?")
        r.expectTrue(login.totp != nil, "cipher camel login.totp EncString?")
        r.expectTrue(login.passwordRevisionDate != nil, "cipher camel login.passwordRevisionDate Date?")
        r.expect(login.uris?.count, 1, "cipher camel login.uris count")
        r.expectTrue(login.uris?[0].uri != nil, "cipher camel login.uris[0].uri EncString")
        r.expect(login.uris?[0].match, .host, "cipher camel login.uris[0].match == host (1)")
        r.expect(login.fido2Credentials?.count, 1, "cipher camel fido2Credentials count")
        let fido = login.fido2Credentials?[0]
        r.expectTrue(fido?.credentialId != nil, "cipher camel fido credentialId EncString")
        r.expectTrue(fido?.userName != nil, "cipher camel fido userName EncString")
        r.expectTrue(fido?.creationDate != nil, "cipher camel fido creationDate is plaintext Date")

        // fields
        r.expect(c.fields?.count, 1, "cipher camel fields count")
        r.expect(c.fields?[0].type, .hidden, "cipher camel field type == hidden")
        r.expectTrue(c.fields?[0].linkedId == nil, "cipher camel field linkedId nil")
    } catch { r.expectTrue(false, "cipher camel threw: \(error)") }

    // Login cipher — PascalCase
    do {
        let c = try decoder.decode(CipherResponse.self, from: TestJSON.cipherLoginPascal().data(using: .utf8)!)
        r.expect(c.id, "cipher-2", "cipher pascal id")
        r.expect(c.type, .login, "cipher pascal type == login")
        r.expect(c.folderId, "folder-7", "cipher pascal folderId")
        r.expect(c.favorite, false, "cipher pascal favorite")
        r.expect(c.name.type, .aesCbc256_HmacSha256_B64, "cipher pascal name is EncString")
        r.expectTrue(c.notes != nil, "cipher pascal notes EncString?")
        r.expectTrue(c.key == nil, "cipher pascal key nil")
        guard let login = c.login else {
            r.expectTrue(false, "cipher pascal login present"); return
        }
        r.expectTrue(login.username != nil, "cipher pascal login.username EncString?")
        r.expectTrue(login.totp == nil, "cipher pascal login.totp nil")
        r.expectTrue(login.passwordRevisionDate == nil, "cipher pascal login.passwordRevisionDate nil")
        r.expect(login.uris?.count, 1, "cipher pascal login.uris count")
        r.expect(login.uris?[0].match, .exact, "cipher pascal login.uris[0].match == exact (3)")
        r.expect(login.fido2Credentials?.count, 0, "cipher pascal fido2Credentials empty")
        r.expectTrue(c.revisionDate.timeIntervalSince1970 > 0, "cipher pascal revisionDate is Date (no fractional)")
    } catch { r.expectTrue(false, "cipher pascal threw: \(error)") }

    // FolderResponse — both casings
    do {
        let f = try decoder.decode(FolderResponse.self, from: TestJSON.folderCamel().data(using: .utf8)!)
        r.expect(f.id, "folder-1", "folder camel id")
        r.expect(f.name.type, .aesCbc256_HmacSha256_B64, "folder camel name is EncString")
        r.expectTrue(f.revisionDate.timeIntervalSince1970 > 0, "folder camel revisionDate is Date")
    } catch { r.expectTrue(false, "folder camel threw: \(error)") }

    do {
        let f = try decoder.decode(FolderResponse.self, from: TestJSON.folderPascal().data(using: .utf8)!)
        r.expect(f.id, "folder-2", "folder pascal id")
        r.expect(f.name.type, .aesCbc256_HmacSha256_B64, "folder pascal name is EncString")
    } catch { r.expectTrue(false, "folder pascal threw: \(error)") }
}
