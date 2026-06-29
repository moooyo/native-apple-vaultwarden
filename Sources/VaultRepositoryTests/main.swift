import Foundation
import VaultRepository

/// Headless test runner for VaultRepository (no XCTest on this CLT host).
/// Exercises the auth (login / 2FA / unlock), vault CRUD, lock, and DI-container paths
/// end-to-end against a fake AuthAPI/VaultAPI + a real KeyVault + a temp-DB VaultStore +
/// in-memory KeychainBridge seams.
func runAllTests() async -> Int {
    var r = TestRunner()

    // Login pipeline: happy path (PBKDF2), Argon2id rejection (D6), 2FA round-trip.
    await checkLoginHappyPath(&r)
    await checkArgon2idRejected(&r)
    await checkTwoFactorRequired(&r)
    await checkTwoFactorWithoutPending(&r)

    // Vault CRUD + lock.
    await checkCreateCipher(&r)
    await checkCreateCipherLockedFails(&r)
    await checkLock(&r)

    // DI container resolution via the Has* protocols.
    await checkServiceContainer(&r)

    return r.summary()
}

let failures = await runAllTests()
if failures != 0 { exit(1) }
