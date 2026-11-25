import Foundation
import UIShared
import VaultModels
import VaultRepository

func checkVaultHealthReport(_ r: inout TestRunner) async {
    let suffix = "mQ7!rV3$st8%W2"
    let composed = "é\(suffix)"
    let decomposed = "e\u{301}\(suffix)"
    func login(_ id: String, _ name: String, _ password: String?) -> PlaintextCipher {
        .init(id: id, name: name, login: .init(password: password))
    }
    let ciphers = [
        login("z", "Zulu", composed), login("2", "Alpha", composed),
        login("1", "Alpha", "Password1!"), login("3", "Alpha", "Password1!"),
        login("weak", "Beta", "aaaaaaaaaaaa"), login("repeat", "Repeat Pattern", "violet|ViOlet|"),
        login("normalization", "Different normalization", decomposed),
        login("case", "Different case", "É\(suffix)"), login("space", "Trailing space", "\(composed) "),
        login("empty", "Empty", ""), login("passkey", "Passkey Only", nil),
        .init(id: "org", name: "Organization", organizationID: "org", login: .init(password: composed)),
        .init(id: "archived", name: "Archived", login: .init(password: composed), archivedDate: .now),
        .init(id: "trash", name: "Trashed", login: .init(password: composed), deletedDate: .now),
        .init(id: "not-login", type: CipherType.secureNote.rawValue, name: "Note", login: .init(password: composed)),
        .init(name: "Unsaved", login: .init(password: composed))
    ]
    let lease = AccountSessionLease(accountID: "test", generation: 0)
    let vault = FakeVaultService(stored: ciphers)
    let auth = FakeAuthService(unlocked: true)
    do {
        let report = try VaultHealthReport.analyze(ciphers)
        r.expect(report.checkedCount, 9, "health report: checks only active personal logins with saved passwords")
        r.expect(report.weakCount, 4, "health report: counts weak logins, including a reused weak password")
        r.expect(report.reusedCount, 4, "health report: reuse requires exact bytes, not normalized text, case or spaces")
        r.expect(report.findings.map(\.id), ["1", "2", "3", "weak", "repeat", "z"], "health report: orders by name then ID")
        r.expect(report.findings.map(\.reuseCount), [2, 2, 2, 1, 1, 2], "health report: reuse count includes the current login")
        r.expect(report.findings.map(\.weaknesses), [[.tooShort, .commonPattern], [], [.tooShort, .commonPattern],
                                                    [.limitedCharacterVariety], [.repeatedPattern], []], "health report: exposes reasons only")
        r.expect(try VaultHealthReport.analyze(Array(ciphers.reversed())), report, "health report: independent of input order")
        r.expect(try await VaultHealthReport.load(auth: auth, vault: vault, for: lease), report, "health report: scans the local vault")
        r.expect(await vault.ciphersCallCount, 1, "health report: uses one active-cipher read")
        r.expect(await vault.syncCallCount, 0, "health report: does not sync")
    } catch {
        r.expectTrue(false, "health report: the fixture should produce results")
    }

    let otherAccount = AccountSessionLease(accountID: "other", generation: lease.generation)
    let newGeneration = AccountSessionLease(accountID: lease.accountID, generation: lease.generation + 1)
    let changes: [([AccountSessionLease?], Int)] = [([nil], 0), ([otherAccount], 0), ([lease, nil], 1),
                                                   ([lease, otherAccount], 1), ([lease, newGeneration], 1)]
    for (sessions, expectedReads) in changes {
        let auth = HealthReportSessionProbe(sessions: sessions)
        let vault = FakeVaultService(stored: ciphers)
        do {
            _ = try await VaultHealthReport.load(vault: vault, for: lease, currentSession: auth.current)
            r.expectTrue(false, "health report: must reject a missing or replaced lease")
        } catch {
            r.expect(error as? RepositoryError, .locked, "health report: discards results when the lease is lost")
        }
        r.expect(await vault.ciphersCallCount, expectedReads, "health report: checks the lease both before and after reading")
    }

    let pause = PausedAuthSubmission()
    let delayedAuth = HealthReportSessionProbe(sessions: [lease, lease], pauseAfterRead: pause)
    let load = Task { try await VaultHealthReport.load(vault: vault, for: lease, currentSession: delayedAuth.current) }
    await pause.waitUntilStarted()
    load.cancel()
    await pause.finish()
    switch await load.result {
    case .failure(is CancellationError):
        r.expectTrue(true, "health report: cancellation discards the local snapshot")
    default:
        r.expectTrue(false, "health report: cancellation must not publish a report")
    }
}

private actor HealthReportSessionProbe {
    private var sessions: [AccountSessionLease?]
    private let pauseAfterRead: PausedAuthSubmission?
    private var checks = 0

    init(sessions: [AccountSessionLease?], pauseAfterRead: PausedAuthSubmission? = nil) {
        self.sessions = sessions
        self.pauseAfterRead = pauseAfterRead
    }

    func current() async -> AccountSessionLease? {
        checks += 1
        if checks == 2, let pauseAfterRead { await pauseAfterRead.pause() }
        return sessions.isEmpty ? nil : sessions.removeFirst()
    }
}
