import Foundation
@testable import CryptoCore

func checkKDF(_ r: inout TestRunner) {
    let email = "user@example.com"
    let password = "Password123!"
    let iters = 5000

    // test_deriveMasterKey_goldenVector
    do {
        let mk = try KDF.deriveMasterKey(password: password, email: email, iterations: iters)
        r.expect(Data(mk).hexString,
                 "b86c2ee9e33113c09c31c92d5f288a989a56d2485e76cc81f5607dea299a5da4",
                 "KDF.deriveMasterKey golden vector")
    } catch {
        r.expectTrue(false, "KDF.deriveMasterKey threw: \(error)")
    }

    // test_emailIsTrimmedAndLowercased
    do {
        let mk1 = try KDF.deriveMasterKey(password: password, email: "  USER@Example.com ", iterations: iters)
        let mk2 = try KDF.deriveMasterKey(password: password, email: email, iterations: iters)
        r.expect(mk1, mk2, "KDF.deriveMasterKey trims + lowercases email")
    } catch {
        r.expectTrue(false, "KDF.deriveMasterKey email-normalization threw: \(error)")
    }

    // test_serverAuthHash_goldenVector
    do {
        let mk = try KDF.deriveMasterKey(password: password, email: email, iterations: iters)
        let hash = try KDF.masterPasswordHash(masterKey: mk, password: password, purpose: .serverAuthorization)
        r.expect(hash, "5XhkzlRm282dCTYHuni4Qw6J4PYChL0z7Cx+kKqE50w=",
                 "KDF.masterPasswordHash serverAuthorization golden vector")
    } catch {
        r.expectTrue(false, "KDF.masterPasswordHash server threw: \(error)")
    }

    // test_localAuthHash_goldenVector
    do {
        let mk = try KDF.deriveMasterKey(password: password, email: email, iterations: iters)
        let hash = try KDF.masterPasswordHash(masterKey: mk, password: password, purpose: .localAuthorization)
        r.expect(hash, "TX2MDMqyhAyYAET/GN1etxjUsD/22fWXWT9YOkktUA4=",
                 "KDF.masterPasswordHash localAuthorization golden vector")
    } catch {
        r.expectTrue(false, "KDF.masterPasswordHash local threw: \(error)")
    }

    for invalid in [Int.min, -1, 0, 4_999] {
        r.expectThrowsError(CryptoError.insufficientKdfParameters, "KDF rejects \(invalid) iterations below the minimum") {
            _ = try KDF.deriveMasterKey(password: password, email: email, iterations: invalid)
        }
    }

    do {
        let masterKey = try KDF.deriveMasterKey(password: password, email: email, iterations: 2_000_000)
        r.expect(Data(masterKey).hexString,
                 "5b388f3cb9b74a6d2ce2380031cf91a4bad30cc7d5ffdb8b4646d3e1763959cd",
                 "KDF uses the exact requested count at the inclusive maximum")
    } catch {
        r.expectTrue(false, "KDF at the maximum threw: \(error)")
    }

    for invalid in [2_000_001, Int(UInt32.max) + 1, Int.max] {
        r.expectThrowsError(CryptoError.excessiveKdfParameters, "KDF rejects \(invalid) iterations above the maximum") {
            _ = try KDF.deriveMasterKey(password: password, email: email, iterations: invalid)
        }
    }

    for iterations in [5_000, 599_999] {
        r.expectTrue(KDF.isPBKDF2BelowRecommendation(iterations: iterations), "KDF advises on supported count \(iterations)")
    }
    for iterations in [4_999, 600_000, 2_000_000, 2_000_001] {
        r.expectTrue(!KDF.isPBKDF2BelowRecommendation(iterations: iterations), "KDF does not advise on count \(iterations)")
    }
}
