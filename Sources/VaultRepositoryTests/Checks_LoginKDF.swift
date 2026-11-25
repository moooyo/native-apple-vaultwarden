import CryptoCore
import VaultModels
import VaultRepository

func checkPBKDF2LoginLimits(_ runner: inout TestRunner) async {
    for iterations in [5_000, 599_999] {
        do {
            let masterKey = try KDF.deriveMasterKey(password: Fixtures.password, email: Fixtures.email, iterations: iterations)
            let wrappedKey = try SymmetricCrypto.encrypt(Fixtures.userKeyData(), using: KeyStretch.stretchMasterKey(masterKey))
            let token = TokenResponse(accessToken: "kdf-fixture-access", expiresIn: 300, refreshToken: "kdf-fixture-refresh",
                                      tokenType: "Bearer", key: wrappedKey, privateKey: nil, kdf: 0, kdfIterations: iterations)
            let harness = try await Fixtures.makeHarness(tokenResults: [.success(token)], iterations: iterations)
            defer { Fixtures.cleanup(harness.dir) }
            let login = try await harness.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
            runner.expect(login, .success, "Login accepts \(iterations) PBKDF2 rounds")
            let saved = await harness.auth.session?.kdfIterations
            runner.expect(saved, iterations, "Login preserves the account's KDF count")
            runner.expectTrue(saved.map(KDF.isPBKDF2BelowRecommendation(iterations:)) == true,
                              "Account settings warn about the accepted count")
            await harness.auth.lock()
            try await harness.auth.unlockWithMasterPassword(Fixtures.password)
            runner.expectTrue(await harness.auth.isUnlocked(), "Local unlock accepts \(iterations) PBKDF2 rounds")
            runner.expectTrue(await harness.api.refreshTokensUsed.isEmpty, "Local unlock does not need token renewal")
        } catch { runner.expectTrue(false, "Login at \(iterations) PBKDF2 rounds threw: \(error)") }
    }

    for (iterations, error) in [(4_999, CryptoError.insufficientKdfParameters),
                                (2_000_001, .excessiveKdfParameters),
                                (Int(UInt32.max) + 1, .excessiveKdfParameters)] {
        do {
            let harness = try await Fixtures.makeHarness(tokenResults: [], iterations: iterations)
            defer { Fixtures.cleanup(harness.dir) }
            await runner.expectThrowsErrorAsync(RepositoryError.underlying(kind: .crypto, description: String(describing: error)),
                                                "Login rejects \(iterations) PBKDF2 rounds before the grant") {
                _ = try await harness.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
            }
            runner.expectTrue(await harness.api.tokenCalls.isEmpty, "Invalid KDF never produces a password grant")
            runner.expectTrue(!(await harness.auth.isUnlocked()), "Invalid KDF does not unlock the vault")
        } catch { runner.expectTrue(false, "Invalid KDF fixture failed: \(error)") }
    }
}
