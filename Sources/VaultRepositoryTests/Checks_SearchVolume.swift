import CryptoCore
import Foundation
import VaultModels
import VaultRepository
import VaultStore

/// Time the first local query against a freshly seeded, separately keyed personal vault.
func checkLargeVaultSearch(_ runner: inout TestRunner) async {
    let count = 5_000
    let last = count - 1
    let revision = "2026-01-01T00:00:00.000Z"
    do {
        let harness = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())])
        defer { Fixtures.cleanup(harness.dir) }
        _ = try await harness.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        guard let accountID = await harness.auth.session?.accountID else {
            runner.expectTrue(false, "Large search fixture has an account")
            return
        }
        let accountKey = Fixtures.userKey()
        try await harness.store.upsertCiphers(try (0..<count).map { index in
            let rawKey = try SecureRandom.bytes(64)
            let itemKey = try SymmetricCryptoKey(combined: rawKey)
            func seal(_ value: String) throws -> String {
                try SymmetricCrypto.encrypt(Data(value.utf8), using: itemKey).stringValue
            }
            let blob = try JSONSerialization.data(withJSONObject: ["login": [
                "username": try seal("member-\(index)"),
                "password": try seal("fixture-secret-\(index)"),
                "uris": [["uri": try seal("https://site-\(index).example.test")]]
            ]])
            return CipherRow(id: "login-\(index)", accountID: accountID, type: CipherType.login.rawValue,
                             revisionDate: revision, creationDate: revision, encName: try seal("Login \(index)"),
                             encBlob: String(decoding: blob, as: UTF8.self),
                             encCipherKey: try SymmetricCrypto.encrypt(rawKey, using: accountKey).stringValue)
        })

        let syncCount = await harness.api.syncCallCount
        let start = ContinuousClock.now
        let matches = try await harness.vault.search("SITE-\(last).EXAMPLE.TEST")
        print("First local search over \(count) independently keyed logins: \(start.duration(to: .now))")
        runner.expect(matches.compactMap(\.id), ["login-\(last)"], "Large search matches the encrypted URI")
        runner.expect(matches.first?.login?.password, "fixture-secret-\(last)", "Large search returns the decrypted match")
        runner.expectTrue(try await harness.vault.search("fixture-secret").isEmpty, "Large search excludes passwords")
        runner.expect(await harness.api.syncCallCount, syncCount, "Large search never requests a server sync")
        runner.expectTrue(await harness.api.refreshTokensUsed.isEmpty, "Large search never attempts token renewal")
        await harness.vault.lock()
        await runner.expectThrowsAsync("Locked vault does not return search results") {
            _ = try await harness.vault.search("SITE-\(last).EXAMPLE.TEST")
        }
    } catch {
        runner.expectTrue(false, "Large search fixture threw: \(error)")
    }
}
