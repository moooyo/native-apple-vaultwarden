import Foundation
import VaultModels
import VaultRepository
import UIShared

@MainActor
func checkItemDetailRevealAndCopy(_ r: inout TestRunner) async {
    let cipher = PlaintextCipher(id: "1", name: "GitHub",
                                 login: .init(username: "octocat", password: "s3cr3t"))
    let model = ItemDetailModel(cipher: cipher)

    r.expectFalse(model.revealPassword, "ItemDetail: password hidden by default")
    model.toggleReveal()
    r.expectTrue(model.revealPassword, "ItemDetail: toggleReveal shows password")

    r.expect(model.copyUsername(), "octocat", "ItemDetail: copyUsername returns username")
    r.expect(model.copyPassword(), "s3cr3t", "ItemDetail: copyPassword returns password")
}

@MainActor
func checkItemDetailNoLogin(_ r: inout TestRunner) async {
    // A secure note (no login) → copy accessors return nil; no TOTP.
    let note = PlaintextCipher(id: "9", type: CipherType.secureNote.rawValue, name: "Note")
    let model = ItemDetailModel(cipher: note)

    r.expectNil(model.copyUsername(), "ItemDetail: no username → copyUsername nil")
    r.expectNil(model.copyPassword(), "ItemDetail: no password → copyPassword nil")
    r.expectFalse(model.hasTOTP, "ItemDetail: no login → no TOTP")
    r.expectNil(model.totpCode, "ItemDetail: no TOTP code")
}

@MainActor
func checkItemDetailTOTPGoldenVector(_ r: inout TestRunner) async {
    // RFC 6238 golden vector: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ (raw base32) → SHA-1/6/30.
    // At t=59s the code is 287082; seconds remaining in the 30s window is 30 - (59 % 30) = 1.
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    let cipher = PlaintextCipher(id: "1", name: "TOTP Item",
                                 login: .init(username: "u", password: "p", totp: secret))
    let fixed = Date(timeIntervalSince1970: 59)
    let model = ItemDetailModel(cipher: cipher, now: { fixed })

    r.expectTrue(model.hasTOTP, "ItemDetail: hasTOTP true for valid secret")
    r.expect(model.totpCode, "287082", "ItemDetail: TOTP code matches RFC6238 vector at t=59")
    r.expect(model.totpSecondsRemaining, 1, "ItemDetail: secondsRemaining at t=59 is 1")
    r.expect(model.copyTOTP(), "287082", "ItemDetail: copyTOTP returns the code")
}

@MainActor
func checkItemDetailTOTPInvalidSecret(_ r: inout TestRunner) async {
    // A non-base32 garbage secret should not crash — it simply yields no TOTP.
    let cipher = PlaintextCipher(id: "1", name: "Bad TOTP",
                                 login: .init(username: "u", password: "p", totp: "!!!not base32!!!"))
    let model = ItemDetailModel(cipher: cipher)

    r.expectFalse(model.hasTOTP, "ItemDetail: invalid secret → hasTOTP false")
    r.expectNil(model.totpCode, "ItemDetail: invalid secret → totpCode nil")
    r.expectNil(model.totpSecondsRemaining, "ItemDetail: invalid secret → secondsRemaining nil")
}
