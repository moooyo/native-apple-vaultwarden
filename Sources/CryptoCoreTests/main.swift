import Foundation
import CryptoCore

func runAllTests() -> Int {
    var r = TestRunner()

    // Smoke
    r.expect(CryptoCore.version, "0.1.0", "module loads")

    checkEncryptionType(&r)
    checkSecureBytes(&r)
    checkSecureRandom(&r)
    checkEncString(&r)
    checkEncStringCodable(&r)
    checkPBKDF2(&r)
    checkKDF(&r)
    checkKeyStretch(&r)
    checkSendCryptography(&r)
    checkSymmetricCrypto(&r)
    checkPasswordProtectedExport(&r)
    checkGoldenVector(&r)

    return r.summary()
}

let failures = runAllTests()
if failures != 0 { exit(1) }
