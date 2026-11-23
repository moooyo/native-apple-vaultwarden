import AppKit
import SwiftUI
import UIShared
import VaultRepository

extension ReviewBoards {
    func checkTouchIDSettingsAndFallback() async throws {
        let renderer = WindowRenderer(directory: FileManager.default.temporaryDirectory, dark: false)
        let service = FakeAuthService(email: "touchid@example.invalid", unlocked: true)
        let settings = SettingsModel()
        let changes = ReviewTouchIDChanges()
        let (preferences, suite) = try isolatedPreferences()
        defer { preferences.removePersistentDomain(forName: suite) }
        try await renderer.inspect(width: 720, height: 465, title: "Settings") {
            MacSettingsView(auth: service, syncModel: SyncStatusModel(vault: FakeVaultService()), settings: settings,
                            timeoutSettings: MacSessionTimeoutModel(defaults: preferences), initialPane: .security,
                            onSetTouchID: { enabled in
                                try await changes.request(enabled)
                                settings.biometricUnlockEnabled = enabled
                            }, onSync: {}, onAuthChange: {})
                .defaultAppStorage(preferences)
                .environment(\.macTouchIDAvailabilityOverride, true)
        } perform: { window in
            defer { changes.resolve(succeeds: false) }
            try await pressTouchIDSwitch(in: window, state: .off)
            try await waitFor("Touch ID enable is pending") { changes.isPending && touchIDSwitch(in: window)?.isEnabled == false }
            try require(changes.attempts == [true] && !settings.biometricUnlockEnabled && touchIDSwitch(in: window)?.state == .off,
                        "Touch ID does not enable before enrollment completes")
            changes.resolve(succeeds: false)
            try await waitFor("rejected enrollment keeps the native Touch ID switch off") {
                touchIDSwitch(in: window)?.state == .off && touchIDSwitch(in: window)?.isEnabled == true
            }

            try await pressTouchIDSwitch(in: window, state: .off)
            try await waitFor("retry Touch ID enrollment") { changes.isPending }
            changes.resolve(succeeds: true)
            try await pressTouchIDSwitch(in: window, state: .on)
            try await waitFor("Touch ID removal is pending") { changes.isPending && touchIDSwitch(in: window)?.isEnabled == false }
            try require(settings.biometricUnlockEnabled && touchIDSwitch(in: window)?.state == .on,
                        "Touch ID remains enabled until removal succeeds")
            changes.resolve(succeeds: false)
            try await pressTouchIDSwitch(in: window, state: .on)
            try await waitFor("retry Touch ID removal") { changes.isPending }
            changes.resolve(succeeds: true)
            try await waitFor("successful removal turns off the native Touch ID switch") {
                !settings.biometricUnlockEnabled && touchIDSwitch(in: window)?.state == .off
            }
            try require(changes.attempts == [true, true, false, false], "the native switch submits each requested change once")
        }

        await service.lock()
        await service.setUnlockBiometricsError(RepositoryError.authenticationFailed)
        let model = UnlockModel(auth: service)
        var unlocked = false
        try await renderer.inspect(width: 560, height: 500) {
            MacUnlockView(model: model, biometricsEnabled: true) { unlocked = true }
                .environment(\.macTouchIDAvailabilityOverride, true)
        } perform: { window in
            let fieldID = "unlock.password"
            @MainActor func masterField() -> NSSecureTextField? {
                touchIDSubviews(in: window).compactMap { $0 as? NSSecureTextField }
                    .first { !$0.isHiddenOrHasHiddenAncestor && $0.accessibilityIdentifier() == fieldID }
            }
            let touchID = try await reviewAX(.button, named: "unlock.touch-id", in: window)
            try require(touchID.accessibilityPerformPress?() == true, "activate Touch ID on the unlock form")
            try await waitFor("a failed Touch ID attempt returns to the unlock form") { model.errorMessage != nil }
            try require(await service.biometricCalls.count == 1 && !unlocked, "a rejected biometric request cannot unlock the vault")
            try await waitFor("master password is editable after Touch ID failure") { masterField()?.isEnabled == true }
            guard let field = masterField(), window.makeFirstResponder(field), let editor = field.currentEditor() as? NSTextView else {
                throw CheckFailure(message: "Missing the master password fallback")
            }
            let credential = "touch-id-fallback-fixture"
            let pasteboard = NSPasteboard.withUniqueName()
            defer { pasteboard.releaseGlobally() }
            try require(pasteboard.setString(credential, forType: .string) && editor.readSelection(from: pasteboard, type: .string),
                        "enter the synthetic master password in the native fallback field")
            editor.doCommand(by: #selector(NSResponder.insertNewline(_:)))
            try await waitFor("master password unlock completes") { unlocked }
            try require(await service.unlockMasterCalls == [credential], "master password fallback reaches the service")
        }
        print("Touch ID: delayed and rejected settings changes, successful removal, and master password fallback passed.")
    }

    private func pressTouchIDSwitch(in window: NSWindow, state: NSControl.StateValue) async throws {
        try await waitFor("Touch ID switch is enabled with its expected state") {
            touchIDSwitch(in: window)?.state == state && touchIDSwitch(in: window)?.isEnabled == true
        }
        touchIDSwitch(in: window)?.performClick(nil)
    }

    private func touchIDSwitch(in window: NSWindow) -> NSSwitch? {
        window.contentView?.layoutSubtreeIfNeeded()
        let switches = touchIDSubviews(in: window).compactMap { $0 as? NSSwitch }.filter { !$0.isHiddenOrHasHiddenAncestor }
        return switches.first { $0.accessibilityIdentifier() == "settings.touch-id" }
            ?? switches.min { $0.convert($0.bounds, to: nil).midY < $1.convert($1.bounds, to: nil).midY }
    }

    private func touchIDSubviews(in window: NSWindow) -> [NSView] {
        var pending = window.contentView.map { [$0] } ?? []
        var views: [NSView] = []
        while let view = pending.popLast() {
            views.append(view)
            pending += view.subviews
        }
        return views
    }
}

@MainActor private final class ReviewTouchIDChanges {
    private(set) var attempts: [Bool] = []
    private var continuation: CheckedContinuation<Void, any Error>?
    var isPending: Bool { continuation != nil }

    func request(_ enabled: Bool) async throws {
        attempts.append(enabled)
        try await withCheckedThrowingContinuation { continuation = $0 }
    }

    func resolve(succeeds: Bool) {
        let pending = continuation
        continuation = nil
        if succeeds { pending?.resume() }
        else { pending?.resume(throwing: RepositoryError.authenticationFailed) }
    }
}
