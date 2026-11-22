import Foundation
import VaultRepository
import VaultStore

func checkGeneratorHistoryIsolation(_ runner: inout TestRunner) async {
    do {
        let harness = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())])
        defer { Fixtures.cleanup(harness.dir) }
        _ = try await harness.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        let snapshot = try await harness.vault.generatorHistory()
        let entry = GeneratorHistoryEntry(kind: .passphrase, value: "only-in-the-unlocked-vault")
        try await harness.vault.addGeneration(entry, session: snapshot.session)
        try await harness.vault.addGeneration(entry, session: snapshot.session)
        let history = try await harness.vault.generatorHistory()
        runner.expect(history.entries, [entry], "Generator history: recording an entry is idempotent")
        let payloads = try await harness.store.encryptedGenerationHistory(accountID: snapshot.session.accountID)
        runner.expect(payloads.count, 1, "Generator history: exactly one local record")
        runner.expectTrue(payloads.first?.hasPrefix("2.") == true, "Generator history: payload uses the vault key")
        runner.expectTrue(!payloads.contains(where: { $0.contains(entry.value) }), "Generator history: no plaintext in the payload")

        let other = AccountSessionLease(accountID: "different", generation: snapshot.session.generation)
        await runner.expectThrowsErrorAsync(RepositoryError.notAuthenticated, "Generator history: wrong account cannot write") {
            try await harness.vault.addGeneration(entry, session: other)
        }
        await harness.vault.lock()
        await runner.expectThrowsErrorAsync(RepositoryError.locked, "Generator history: cannot read while locked") {
            _ = try await harness.vault.generatorHistory()
        }
        try await harness.auth.unlockWithMasterPassword(Fixtures.password)
        await runner.expectThrowsErrorAsync(RepositoryError.notAuthenticated, "Generator history: stale scene cannot clear") {
            try await harness.vault.clearGeneratorHistory(session: snapshot.session)
        }
        let unlocked = try await harness.vault.generatorHistory()
        runner.expect(unlocked.entries, [entry], "Generator history: same account can unlock its history")
        try await harness.vault.clearGeneratorHistory(session: unlocked.session)
        let cleared = try await harness.vault.generatorHistory()
        runner.expectTrue(cleared.entries.isEmpty, "Generator history: clear removes records")
        try await harness.vault.addGeneration(entry, session: unlocked.session)
        await harness.auth.logout()
        let remaining = try await harness.store.encryptedGenerationHistory(accountID: snapshot.session.accountID)
        runner.expectTrue(remaining.isEmpty, "Generator history: logout purges the account's history")
    } catch {
        runner.expectTrue(false, "Generator history lifecycle failed: \(error)")
    }
}
