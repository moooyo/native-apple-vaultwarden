import Foundation
import VaultReader

func runAllTests() async -> Int {
    var r = TestRunner()

    // Password credential: happy path, per-cipher key, error paths, locked.
    await checkPasswordCredential(&r)
    await checkPasswordLocked(&r)

    // Passkey assertion: real Fido2 round-trip + error paths + locked.
    await checkPasskeyAssertion(&r)
    await checkPasskeyLocked(&r)

    // Decrypt one cipher.
    await checkDecryptOneCipher(&r)

    // Biometric unlock path.
    await checkBiometricUnlock(&r)
    await checkBiometricUnlockNotEnabled(&r)

    return r.summary()
}

let failures = await runAllTests()
if failures != 0 { exit(1) }
