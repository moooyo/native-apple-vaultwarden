import Foundation
@testable import CryptoCore

func checkKeyStretch(_ r: inout TestRunner) {
    // test_hkdfExpand_goldenVectors
    let prk = Array<UInt8>(0...31)                       // 00..1f
    let enc = KeyStretch.hkdfExpand(prk: prk, info: "enc", length: 32)
    let mac = KeyStretch.hkdfExpand(prk: prk, info: "mac", length: 32)
    r.expect(Data(enc).hexString,
             "9c5639fac602366b486253191cb7900d7d8e3a1514676b118d5803a11dd97213",
             "HKDF-Expand info=enc golden vector")
    r.expect(Data(mac).hexString,
             "cce388b4ac0f05edee78d40dcbe78a7715640de75ed9ba06942fb42398d6b1f1",
             "HKDF-Expand info=mac golden vector")

    // test_stretchMasterKey_goldenVectors
    let mk = Array(Data(hex: "b86c2ee9e33113c09c31c92d5f288a989a56d2485e76cc81f5607dea299a5da4"))
    let key = KeyStretch.stretchMasterKey(mk)
    r.expect(key.encKey.hexString, "8ec8d572bdc1df1e915f60f45e76a1535c3ad1db52ddd6a6542eb3e6cf8636a4",
             "stretchMasterKey encKey golden vector")
    r.expect(key.macKey.hexString, "194a0f057a41373f7e74b8639f66bf4925b1cfb65186addde6a9b6bb92096432",
             "stretchMasterKey macKey golden vector")

    // test_symmetricKeyFrom64Bytes
    do {
        let combined = Data((0..<64).map { UInt8($0) })
        let symKey = try SymmetricCryptoKey(combined: combined)
        r.expect(symKey.encKey, combined.prefix(32), "SymmetricCryptoKey(combined:) encKey is prefix(32)")
        r.expect(symKey.macKey, combined.suffix(32), "SymmetricCryptoKey(combined:) macKey is suffix(32)")
    } catch {
        r.expectTrue(false, "SymmetricCryptoKey(combined:) threw: \(error)")
    }

    // test_symmetricKeyWrongLengthThrows
    r.expectThrowsError(CryptoError.invalidKeyLength, "SymmetricCryptoKey(combined:) wrong length throws") {
        _ = try SymmetricCryptoKey(combined: Data(count: 50))
    }
}
