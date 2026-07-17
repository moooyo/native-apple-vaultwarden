import Foundation
import VaultStore
import VaultReader

/// One-time-code fulfillment decrypts the selected login's TOTP and uses the injected
/// instant, so the result is deterministic and does not depend on wall-clock timing.
func checkOneTimeCode(_ r: inout TestRunner) async {
    let (store, dir): (VaultStore, URL)
    do { (store, dir) = try await Fixtures.freshStore() }
    catch { r.expectTrue(false, "oneTimeCode freshStore threw: \(error)"); return }
    defer { Fixtures.cleanup(dir) }

    do {
        try await store.upsertCiphers([
            Fixtures.loginRow(
                id: "otp-1",
                name: "OTP Login",
                username: "alice",
                password: "password",
                totp: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
            ),
            Fixtures.loginRow(
                id: "no-otp",
                name: "Password Only",
                username: "bob",
                password: "password"
            ),
            Fixtures.loginRow(
                id: "bad-otp",
                name: "Malformed OTP",
                username: "eve",
                password: "password",
                totp: "not valid base32!"
            ),
        ])
    } catch {
        r.expectTrue(false, "oneTimeCode seed threw: \(error)"); return
    }

    let reader = VaultReader(
        store: store,
        keyVault: await Fixtures.unlockedVault(),
        keychain: makeFakeKeychain()
    )

    do {
        let code = try await reader.oneTimeCode(
            for: "otp-1",
            at: Date(timeIntervalSince1970: 59)
        )
        r.expect(code, "287082", "oneTimeCode RFC 6238 value at injected instant")
    } catch {
        r.expectTrue(false, "oneTimeCode happy path threw: \(error)")
    }

    await r.expectThrowsErrorAsync(
        VaultReaderError.noOneTimeCode,
        "oneTimeCode missing TOTP"
    ) {
        _ = try await reader.oneTimeCode(for: "no-otp", at: Date(timeIntervalSince1970: 59))
    }
    await r.expectThrowsErrorAsync(
        VaultReaderError.malformed,
        "oneTimeCode malformed TOTP"
    ) {
        _ = try await reader.oneTimeCode(for: "bad-otp", at: Date(timeIntervalSince1970: 59))
    }
    await r.expectThrowsErrorAsync(
        VaultReaderError.notFound,
        "oneTimeCode missing cipher"
    ) {
        _ = try await reader.oneTimeCode(for: "missing", at: Date(timeIntervalSince1970: 59))
    }

    let lockedReader = VaultReader(
        store: store,
        keyVault: Fixtures.lockedVault(),
        keychain: makeFakeKeychain()
    )
    await r.expectThrowsErrorAsync(VaultReaderError.locked, "oneTimeCode locked") {
        _ = try await lockedReader.oneTimeCode(
            for: "otp-1",
            at: Date(timeIntervalSince1970: 59)
        )
    }
}
