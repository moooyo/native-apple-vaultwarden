import Foundation
@testable import CryptoCore

func checkGoldenVector(_ r: inout TestRunner) {
    // test_fullUnlockChain_synthetic
    do {
        // 1. derive master key (PBKDF2) from the planning golden vector
        let mk = try KDF.deriveMasterKey(password: "Password123!",
                                         email: "user@example.com",
                                         iterations: 5000)
        r.expect(Data(mk).hexString,
                 "b86c2ee9e33113c09c31c92d5f288a989a56d2485e76cc81f5607dea299a5da4",
                 "GoldenVector full chain: master key matches")

        // 2. stretch into a SymmetricCryptoKey
        let stretched = KeyStretch.stretchMasterKey(mk)

        // 3. a synthetic 64-byte UserKey, "protected" under the stretched key
        let userKey = Data((0..<64).map { UInt8(($0 &* 3 &+ 1) & 0xff) })
        let protectedUserKey = try SymmetricCrypto.encrypt(userKey, using: stretched)

        // 4. simulate the wire round-trip and decrypt the protected user key
        let wire = protectedUserKey.stringValue
        let recovered = try SymmetricCrypto.decrypt(try EncString(parsing: wire), using: stretched)
        r.expect(recovered, userKey, "GoldenVector full chain: protected user key recovers")

        // 5. and the recovered 64 bytes form a usable SymmetricCryptoKey
        let userSymKey = try SymmetricCryptoKey(combined: recovered)
        let secret = Data("a vault item field".utf8)
        let enc = try SymmetricCrypto.encrypt(secret, using: userSymKey)
        r.expect(try SymmetricCrypto.decrypt(enc, using: userSymKey), secret,
                 "GoldenVector full chain: vault field round-trips under user key")
    } catch {
        r.expectTrue(false, "GoldenVector full chain threw: \(error)")
    }
}
