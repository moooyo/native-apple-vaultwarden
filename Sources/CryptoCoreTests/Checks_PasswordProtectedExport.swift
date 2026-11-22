import Foundation
import CryptoCore

func checkPasswordProtectedExport(_ runner: inout TestRunner) {
    let password = " Backup-\u{2603}! "
    let plaintext = Data(#"{"encrypted":false,"folders":[],"items":[]}"#.utf8)
    let validation = "2.ICEiIyQlJicoKSorLC0uLw==|2NdHvOU3rfL0zMz8qhUTHhOU5Ww7X4ucwMnMKRlhWXChylx+FJkFrJ+PTAgyx4kh|d7ekK0fo0z1R2hPaJKQRD+q6cc1Hzwdr168PkX8B+tM="
    let payload = "2.MDEyMzQ1Njc4OTo7PD0+Pw==|9AcvaXsM+85/jajoY9VINRKTsa6gqY2niHecS96hMPXQ3CdIVzSa0GM2Ht/WO+H2|zqUxfOLTKmtNm9fXg+FNzvtdqNtEc9KHJ2BU7ICX95M="
    let fields: [String: Any] = ["encrypted": true, "passwordProtected": true,
                                 "salt": "ABEiM0RVZneImaq7zN3u/w==", "kdfType": 0, "kdfIterations": 5_000,
                                 "encKeyValidation_DO_NOT_EDIT": validation, "data": payload]
    func fixture(_ overrides: [String: Any] = [:]) throws -> Data {
        try JSONSerialization.data(withJSONObject: fields.merging(overrides) { _, new in new })
    }

    do {
        runner.expect(try PasswordProtectedExport.decrypt(fixture(), password: password), plaintext,
                      "Password-protected JSON decrypts an independent PBKDF2 / HKDF / CBC-HMAC vector")
        let export = try PasswordProtectedExport.encrypt(plaintext, password: password)
        let envelope = try JSONSerialization.jsonObject(with: export) as? [String: Any]
        runner.expect(envelope?["kdfIterations"] as? Int, 600_000, "New exports use the Bitwarden PBKDF2 default")
        runner.expect(envelope?["kdfType"] as? Int, 0, "Password-protected exports declare PBKDF2")
        runner.expect(envelope?["passwordProtected"] as? Bool, true, "Password-protected exports are portable")
        runner.expect(try PasswordProtectedExport.decrypt(export, password: password), plaintext,
                      "Password-protected export round-trip preserves the original JSON bytes")
    } catch {
        runner.expectTrue(false, "Password-protected export vector or round-trip failed: \(error)")
    }

    runner.expectThrowsError(PasswordProtectedExportError.authenticationFailed, "File passwords are not normalized") {
        _ = try PasswordProtectedExport.decrypt(fixture(), password: password.trimmingCharacters(in: .whitespaces))
    }
    runner.expectThrowsError(PasswordProtectedExportError.authenticationFailed, "Payload MAC is checked independently") {
        let altered = payload.replacingOccurrences(of: "|zqU", with: "|AqU")
        _ = try PasswordProtectedExport.decrypt(fixture(["data": altered]), password: password)
    }
    runner.expectThrowsError(PasswordProtectedExportError.authenticationFailed, "Validation must decrypt to a UUID") {
        _ = try PasswordProtectedExport.decrypt(fixture(["encKeyValidation_DO_NOT_EDIT": payload]), password: password)
    }
    runner.expectThrowsError(PasswordProtectedExportError.unsupportedFormat, "Account-bound exports are not portable") {
        let account = Data(#"{"encrypted":true,"folders":[],"items":[]}"#.utf8)
        _ = try PasswordProtectedExport.decrypt(account, password: password)
    }
    runner.expectThrowsError(PasswordProtectedExportError.unsupportedKDF, "Unimplemented KDFs are not silently downgraded") {
        _ = try PasswordProtectedExport.decrypt(fixture(["kdfType": 1]), password: password)
    }
    for iterations in [4_999, 2_000_001, Int.max] {
        runner.expectThrowsError(PasswordProtectedExportError.unsupportedIterations, "File KDF cost is bounded") {
            _ = try PasswordProtectedExport.decrypt(fixture(["kdfIterations": iterations]), password: password)
        }
    }
    runner.expectThrowsError(PasswordProtectedExportError.invalidEnvelope, "Untrusted malformed EncStrings are rejected") {
        _ = try PasswordProtectedExport.decrypt(fixture(["data": "2." + String(repeating: "|", count: 5_000)]),
                                                password: password)
    }
    runner.expectThrowsError(PasswordProtectedExportError.emptyPassword, "Blank file passwords cannot create unreadable exports") {
        _ = try PasswordProtectedExport.encrypt(plaintext, password: "    ")
    }
}
