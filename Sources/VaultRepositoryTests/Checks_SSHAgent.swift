import Foundation
import VaultModels
import VaultRepository
import VaultStore

func checkSSHAgentVaultScope(_ runner: inout TestRunner) async {
    do {
        let fixture = try await Fixtures.makeHarness(tokenResults: [.success(Fixtures.tokenResponse())])
        defer { Fixtures.cleanup(fixture.dir) }
        _ = try await fixture.auth.login(email: Fixtures.email, password: Fixtures.password, server: Fixtures.server)
        guard let lease = await fixture.auth.unlockedSessionLease() else {
            runner.expectTrue(false, "SSH Agent: the fixture has an unlocked lease")
            return
        }
        let privateValue = "Synthetic private bytes"
        let publicValue = "Synthetic public bytes"
        let serverAccount = lease.accountID
        let date = "2026-11-12T00:00:00.000Z"
        let nextDate = "2026-11-13T00:00:00.000Z"
        let blob = try JSONEncoder().encode(["sshKey": ["privateKey": Fixtures.enc(privateValue), "publicKey": Fixtures.enc(publicValue)]])
        let encodedBlob = String(decoding: blob, as: UTF8.self)
        func row(id: String, accountID: String = serverAccount, type: CipherType = .sshKey, reprompt: Int = 0,
                 visible: Bool = true, deleted: String? = nil, archived: String? = nil, revision: String = date,
                 sshBlob: String = encodedBlob) -> CipherRow {
            CipherRow(id: id, accountID: accountID, type: type.rawValue, reprompt: reprompt, viewPassword: visible,
                      revisionDate: revision, creationDate: date, deletedDate: deleted, archivedDate: archived,
                      encName: Fixtures.enc("Synthetic \(id)"), encBlob: sshBlob)
        }
        let foreignAccount = "synthetic-other-account"
        try await fixture.store.upsertAccounts([AccountRow(id: foreignAccount, email: "other@example.invalid", serverURL: "https://other.example.invalid")])
        let eligible = row(id: "eligible")
        try await fixture.store.upsertCiphers([
            eligible, row(id: "requires-reprompt", reprompt: 1), row(id: "restricted", visible: false),
            row(id: "trash", deleted: date), row(id: "archive", archived: date), row(id: "login", type: .login),
            row(id: "foreign", accountID: foreignAccount), row(id: "corrupt", sshBlob: "{")
        ])
        let expected = VaultSSHAgentIdentity(id: "eligible", name: "Synthetic eligible", publicKey: publicValue, revision: date)
        runner.expect(try await fixture.vault.sshAgentIdentities(for: lease), [expected],
                      "SSH Agent: list includes only active allowed SSH items for the active server account")
        #if os(macOS)
        runner.expect(try await fixture.vault.sshAgentItemCount(for: lease), 4, "SSH Agent: count uses live vault item rows, not a loaded signing list")
        runner.expect(try await fixture.vault.sshAgentPublicIdentities(for: lease), [], "SSH Agent: an unindexed item is not guessed")
        try await fixture.vault.refreshSSHAgentPublicIndex(for: lease)
        try await fixture.store.upsertCiphers([eligible])
        runner.expect(try await fixture.vault.sshAgentPublicIdentities(for: lease), [expected], "SSH Agent: unchanged sync rows keep the index")
        #endif
        runner.expect(try await fixture.vault.sshAgentSigningKey(matching: expected, for: lease), privateValue,
                      "SSH Agent: only the matched item supplies its private key")
        runner.expectTrue(try await fixture.vault.isSSHAgentIdentityCurrent(expected, for: lease), "SSH Agent: current identity validates")
        try await fixture.store.upsertCiphers([row(id: "eligible", revision: nextDate)])
        await runner.expectThrowsErrorAsync(RepositoryError.cipherChanged, "SSH Agent: a stale approval cannot load private material") {
            _ = try await fixture.vault.sshAgentSigningKey(matching: expected, for: lease)
        }
        runner.expectTrue(try await !fixture.vault.isSSHAgentIdentityCurrent(expected, for: lease),
                          "SSH Agent: a revision change invalidates an unsent signature")
        #if os(macOS)
        runner.expect(try await fixture.vault.sshAgentPublicIdentities(for: lease), [], "SSH Agent: editing revokes the cached item until it is reindexed")
        try await fixture.vault.refreshSSHAgentPublicIndex(for: lease)
        #endif
        await fixture.auth.lock()
        #if os(macOS)
        guard let locked = await fixture.auth.currentSessionLease() else {
            runner.expectTrue(false, "SSH Agent: a locked account still has an authenticated lease")
            return
        }
        let updated = VaultSSHAgentIdentity(id: expected.id, name: expected.name, publicKey: expected.publicKey, revision: nextDate)
        runner.expect(try await fixture.vault.sshAgentPublicIdentities(for: locked), [updated],
                      "SSH Agent: a locked vault exposes only the encrypted database's matching public index")
        await runner.expectThrowsErrorAsync(RepositoryError.locked, "SSH Agent: an indexed public key cannot load private material while locked") {
            _ = try await fixture.vault.sshAgentSigningKey(matching: updated, for: locked)
        }
        try await fixture.store.upsertCiphers([row(id: "eligible", archived: date, revision: nextDate)])
        runner.expect(try await fixture.vault.sshAgentPublicIdentities(for: locked), [], "SSH Agent: archive removes an indexed key even while locked")
        #endif
        await runner.expectThrowsErrorAsync(RepositoryError.notAuthenticated, "SSH Agent: lock revokes the list lease") {
            _ = try await fixture.vault.sshAgentIdentities(for: lease)
        }
        try await fixture.auth.unlockWithMasterPassword(Fixtures.password)
        await runner.expectThrowsErrorAsync(RepositoryError.notAuthenticated, "SSH Agent: re-unlock does not revive an older lease") {
            _ = try await fixture.vault.sshAgentSigningKey(matching: expected, for: lease)
        }
    } catch {
        runner.expectTrue(false, "SSH Agent vault scope fixture failed: \(error)")
    }
}
