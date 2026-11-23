import AppKit
import Generators
import SwiftUI
import UIShared
import VaultModels
import VaultRepository

extension ReviewBoards {
    func checkQuickCopy() async throws {
        let selected = PlaintextCipher(id: "first", name: "A Selected account", login: .init(username: "first", totp: "%%%"))
        let account = PlaintextCipher(id: "login", name: "B Copy account",
                                      login: .init(username: "review@example.invalid", password: "original fixture value",
                                                   totp: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"))
        let card = PlaintextCipher(id: "card", type: CipherType.card.rawValue, name: "C Copy card",
                                   card: .init(number: "0000 1212", code: "987"))
        let note = PlaintextCipher(id: "note", type: CipherType.secureNote.rawValue, name: "D Copy note", notes: "fixture note\n")
        var reprompt = account
        reprompt.id = "protected"
        reprompt.name = "E Protected account"
        reprompt.reprompt = 1
        var organization = account
        organization.id = "org"
        organization.name = "F Shared account"
        organization.organizationID = "org"
        var archived = account
        archived.archivedDate = .now
        var trashed = account
        trashed.deletedDate = .now
        try require(!MacQuickCopyField.password.isAvailable(in: archived) && !MacQuickCopyField.password.isAvailable(in: trashed),
                    "hidden items must not offer a direct copy")

        let items = [selected, account, card, note, reprompt, organization]
        let service = FakeVaultService(stored: items)
        let accountService = FakeAuthService(email: "review@example.invalid", unlocked: true)
        guard let lease = await accountService.transferSession(), let seed = account.login?.totp else {
            throw CheckFailure(message: "Missing quick-copy fixture credentials")
        }
        let configuration = try TOTP.configuration(from: seed)
        let syncModel = SyncStatusModel(vault: service)
        let suite = "openvault.review.quick-copy.\(UUID().uuidString)"
        guard let preferences = UserDefaults(suiteName: suite) else { throw CheckFailure(message: "Missing quick-copy preferences") }
        defer { preferences.removePersistentDomain(forName: suite) }
        let renderer = WindowRenderer(directory: FileManager.default.temporaryDirectory, dark: false)
        let switchGate = ReviewVaultReadGate()
        let lockGate = ReviewVaultReadGate()
        defer { Task { await switchGate.release(); await lockGate.release() } }
        var copies: [String] = []
        var acceptsCopy = true

        try await renderer.inspect(width: 1050, height: 620, title: "Quick Copy") {
            MacMainView(auth: accountService, vault: service, syncModel: syncModel, dataRevision: 0,
                        workspaceLease: lease, writeQuickCopy: { value, _ in
                            guard acceptsCopy else { return false }
                            copies.append(value)
                            return true
                        }) {}
                .defaultAppStorage(preferences)
        } perform: { window in
            try await waitFor("the native vault list has all six review items") {
                reviewTable(in: window.contentView, matching: { $0.numberOfRows == items.count }) != nil
            }
            guard let table = reviewTable(in: window.contentView, matching: { $0.numberOfRows == items.count }) else {
                throw CheckFailure(message: "Missing native vault list")
            }
            try await waitFor("the first item is selected without copying") { table.selectedRow == 0 }
            try require(reviewNode(.button, named: "mac.quick-copy.password.login", in: window) == nil && copies.isEmpty,
                        "quick-copy buttons start hidden")
            preferences.set(true, forKey: MacClipboardPreference.showsQuickCopyActions)

            let passwordButton = try await reviewAX(.button, named: "mac.quick-copy.password.login", in: window)
            try require(reviewNode(.button, named: "mac.quick-copy.totp.first", in: window) == nil
                            && reviewNode(.button, named: "mac.quick-copy.password.first", in: window) == nil
                            && reviewNode(.button, named: "mac.quick-copy.password.protected", in: window) == nil
                            && reviewNode(.button, named: "mac.quick-copy.totp.protected", in: window) == nil
                            && reviewNode(.button, named: "mac.quick-copy.password.org", in: window) == nil,
                        "empty or malformed, re-prompt and organization values never expose a direct secret-copy button")
            _ = try await reviewAX(.button, named: "mac.quick-copy.username.protected", in: window)
            let label = passwordButton.accessibilityLabel?() ?? passwordButton.accessibilityTitle?() ?? ""
            try require(!label.isEmpty && !label.contains("fixture value"), "accessible names describe the action without disclosing values")

            try sendArrow("\u{F701}", keyCode: 125, to: table, in: window)
            try await waitFor("navigate to the next row by keyboard") { table.selectedRow == 1 }
            try sendArrow("\u{F700}", keyCode: 126, to: table, in: window)
            try await waitFor("return to the first row by keyboard") { table.selectedRow == 0 }
            try require(copies.isEmpty, "keyboard navigation only selects, never copies")

            acceptsCopy = false
            try require(passwordButton.accessibilityPerformPress?() == true, "activate a copy attempt with a rejected clipboard write")
            try await Task.sleep(for: .milliseconds(120))
            let failedCopyStatus: String? = passwordButton.accessibilityValue?()
            try require(copies.isEmpty && (failedCopyStatus ?? "").isEmpty, "a failed write does not advertise a copy")
            acceptsCopy = true

            var refreshed = account
            refreshed.login?.password = "latest fixture value"
            await service.setStored([selected, refreshed, card, note, reprompt, organization])
            try require(passwordButton.accessibilityPerformPress?() == true, "activate an unselected row's password action")
            try await waitFor("copy reads the clicked row's current value rather than its snapshot or the selected item") { copies == ["latest fixture value"] }
            try require(table.selectedRow == 0, "copy does not change the detail selection")

            let start = Date.now
            for (field, id, expected) in [("username", "login", "review@example.invalid"), ("totp", "login", ""),
                                           ("cardNumber", "card", "0000 1212"), ("securityCode", "card", "987"), ("note", "note", "fixture note\n")] {
                let count = copies.count
                let button = try await reviewAX(.button, named: "mac.quick-copy.\(field).\(id)", in: window)
                try require(button.accessibilityPerformPress?() == true, "activate the \(field) shortcut")
                try await waitFor("write the \(field) shortcut only once") { copies.count == count + 1 }
                let possibleCodes = [TOTP.code(for: configuration, at: start), TOTP.code(for: configuration, at: .now)]
                try require(field == "totp" ? copies.last.map(possibleCodes.contains) == true : copies.last == expected,
                            "copy the intended field verbatim or generate the active verification code")
            }

            await service.setStored([selected, reprompt.withID("login"), card, note, reprompt, organization])
            try require(passwordButton.accessibilityPerformPress?() == true, "the previously rendered button still accepts a press")
            try await Task.sleep(for: .milliseconds(120))
            try require(copies.count == 6, "a fresh record that newly requires re-prompt must not be copied")
            await service.setStored([selected, refreshed, card, note, reprompt, organization])

            await service.beforeNextCipherRead { await switchGate.suspend() }
            try require(passwordButton.accessibilityPerformPress?() == true, "start a read before disabling quick copy")
            try await switchGate.waitUntilSuspended("The toggle-race copy did not reach the vault")
            preferences.set(false, forKey: MacClipboardPreference.showsQuickCopyActions)
            try await waitFor("disabling quick copy removes the controls") { reviewNode(.button, named: "mac.quick-copy.password.login", in: window) == nil }
            await switchGate.release()
            try await Task.sleep(for: .milliseconds(120))
            try require(copies.count == 6, "disabling the preference cancels a pending copy")

            preferences.set(true, forKey: MacClipboardPreference.showsQuickCopyActions)
            let restoredButton = try await reviewAX(.button, named: "mac.quick-copy.password.login", in: window)
            await service.beforeNextCipherRead { await lockGate.suspend() }
            try require(restoredButton.accessibilityPerformPress?() == true, "start a read before locking the fixture")
            try await lockGate.waitUntilSuspended("The lock-race copy did not reach the vault")
            await accountService.lock()
            try await accountService.unlockWithMasterPassword("unused fixture value")
            await lockGate.release()
            try await Task.sleep(for: .milliseconds(120))
            try require(copies.count == 6, "a renewed session for the same account must not resurrect the old copy")
        }
        print("Quick copy: default off, keyboard selection, login/card/note copy, failed writes, re-prompt and stale lease rejection passed.")
    }
}

private extension PlaintextCipher {
    func withID(_ id: String) -> Self {
        var copy = self
        copy.id = id
        return copy
    }
}
