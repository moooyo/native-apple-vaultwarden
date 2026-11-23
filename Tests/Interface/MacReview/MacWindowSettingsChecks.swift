import AppKit
import DesignSystem
import SwiftUI
import UIShared

extension ReviewBoards {
    func checkMacWindowSettings(using renderer: WindowRenderer) async throws {
        let (preferences, suite) = try isolatedPreferences()
        defer { preferences.removePersistentDomain(forName: suite) }
        preferences.set(false, forKey: SettingsPreference.showsMenuBar)
        let application = NSApplication.shared
        let delegate = MacApplicationDelegate(defaults: preferences)
        try require(!delegate.applicationShouldTerminateAfterLastWindowClosed(application), "closing the last window defaults to staying open even without a menu extra")

        let initialAppearance = application.appearance
        defer { application.appearance = initialAppearance }
        preferences.set(OpenVaultTheme.dark.rawValue, forKey: OpenVaultPreferenceKey.theme)
        delegate.applicationWillFinishLaunching(Notification(name: NSApplication.willFinishLaunchingNotification, object: application))
        try require(application.appearance?.name == .darkAqua, "the selected theme is applied to AppKit at launch")
        MacAppAppearance.apply(.light, to: application)
        try require(application.appearance?.name == .aqua, "light mode uses Aqua for native controls")
        MacAppAppearance.apply(.system, to: application)
        try require(application.appearance == nil, "following the system removes the appearance override")
        application.appearance = initialAppearance

        try await renderer.inspect(width: 720, height: 330, title: "Window settings", toolbarStyle: .expanded) {
            Form { Section { MacKeepRunningSetting() } }
                .formStyle(.grouped)
                .toggleStyle(.switch)
                .defaultAppStorage(preferences)
        } perform: { window in
            let keepRunning = try await windowSettingSwitch(in: window)
            try require(keepRunning.state == .on, "keep running is enabled by default")
            keepRunning.performClick(nil)
            try await waitFor("disabling keep running affects only last-window closure") {
                delegate.applicationShouldTerminateAfterLastWindowClosed(application)
            }
            try require(!preferences.bool(forKey: SettingsPreference.showsMenuBar), "keep running does not overwrite menu bar visibility")
            keepRunning.performClick(nil)
            try await waitFor("re-enabling keep running affects the next close") {
                !delegate.applicationShouldTerminateAfterLastWindowClosed(application)
            }
        }

        try await renderer.inspect(width: 720, height: 330, title: "Login item unavailable", toolbarStyle: .expanded) {
            Form { Section { MacLaunchAtLoginSetting() } }
                .formStyle(.grouped)
                .toggleStyle(.switch)
        } perform: { window in
            let login = try await windowSettingSwitch(in: window)
            try require(!login.isEnabled, "the review host does not get the real login item service")
        }

        let loginItem = ReviewLoginItem()
        try await renderer.inspect(width: 720, height: 330, title: "Login item settings", toolbarStyle: .expanded) {
            Form { Section { MacLaunchAtLoginSetting() } }
                .formStyle(.grouped)
                .toggleStyle(.switch)
                .environment(\.macLoginItemService, loginItem.service)
        } perform: { window in
            let login = try await windowSettingSwitch(in: window)
            try require(login.isEnabled && login.state == .off && loginItem.updates.isEmpty, "a new login item stays off until the user requests it")
            login.performClick(nil)
            try await waitFor("the explicit opt-in creates one pending login item") { loginItem.updates == [true] && login.state == .on }
            loginItem.status = .notRegistered
            NotificationCenter.default.post(name: NSApplication.didBecomeActiveNotification, object: application)
            try await waitFor("returning from System Settings refreshes the registered state") {
                login.state == .off
            }
            try require(loginItem.updates == [true], "the app does not re-register an externally removed item")
            loginItem.status = .requiresApproval
            NotificationCenter.default.post(name: NSApplication.didBecomeActiveNotification, object: application)
            try await waitFor("a pending registration remains cancellable") { login.state == .on }
            login.performClick(nil)
            try await waitFor("turning off a pending item unregisters it") { loginItem.updates == [true, false] && login.state == .off }
        }

        let loginSettings = MacLoginItemSettings()
        loginItem.status = .enabled
        loginSettings.refresh(using: loginItem.service)
        try require(loginSettings.status == .enabled, "approval is reflected from the system")
        loginItem.status = .requiresApproval
        loginSettings.refresh(using: loginItem.service)
        try require(loginSettings.status == .requiresApproval && loginSettings.status.isRegistered && loginItem.updates == [true, false],
                    "revocation indicates required approval without silent re-registration")
        loginItem.rejectsUpdates = true
        loginSettings.updateRegistration(false, using: loginItem.service)
        try require(loginSettings.status == .requiresApproval && loginSettings.showingError,
                    "failed removal preserves the system state and reports an error")
        loginItem.status = .notRegistered
        loginSettings.updateRegistration(true, using: loginItem.service)
        try require(loginSettings.status == .notRegistered && loginSettings.showingError,
                    "failed registration leaves the item off and reports an error")
        print("Window settings: last-window policy, native appearance, opt-in launch at login, system approval/revocation and failed registration passed.")
    }

    private func windowSettingSwitch(in window: NSWindow) async throws -> NSSwitch {
        let roles: [NSAccessibility.Role] = [.button, .checkBox, .init(rawValue: "AXSwitch")]
        func findSwitch() -> NSSwitch? {
            for role in roles {
                if let control = reviewNode(role, named: nil, in: window, matching: { $0 is NSSwitch }) as? NSSwitch {
                    return control
                }
            }
            return nil
        }
        try await waitFor("find native switch in the one-control review form") { findSwitch() != nil }
        guard let control = findSwitch() else { throw CheckFailure(message: "Missing native window settings switch") }
        return control
    }
}

@MainActor private final class ReviewLoginItem {
    var status: MacLoginItemStatus = .notRegistered
    var updates: [Bool] = []
    var rejectsUpdates = false

    var service: MacLoginItemService {
        .init(status: { self.status }, updateRegistration: { enabled in
            self.updates.append(enabled)
            guard !self.rejectsUpdates else { throw CheckFailure(message: "Login item registration rejected by fixture") }
            self.status = enabled ? .requiresApproval : .notRegistered
        }, openSettings: {})
    }
}
