import AppShared
import SwiftUI

enum MacClipboardPreference {
    static let minimizeAfterCopy = "openvault.mac.minimizeAfterCopy"
    static let showsQuickCopyActions = "openvault.mac.showsQuickCopyActions"
}

struct MacClipboardBehaviorSettings: View {
    @AppStorage(AppShared.Preference.clipboardTimeout) private var clearAfter = 60.0
    @AppStorage(MacClipboardPreference.minimizeAfterCopy) private var minimizeAfterCopy = false

    var body: some View {
        Picker("Clear clipboard", selection: $clearAfter) {
            Text("10 seconds").tag(10.0)
            Text("20 seconds").tag(20.0)
            Text("30 seconds").tag(30.0)
            Text("1 minute").tag(60.0)
            Text("2 minutes").tag(120.0)
            Text("5 minutes").tag(300.0)
            Text("Never").tag(0.0)
        }
        .accessibilityIdentifier("settings.clear-clipboard")

        Toggle(isOn: $minimizeAfterCopy) {
            Text("Minimize when copying to clipboard")
            Text("Minimizes the vault window after copying item data.")
        }
        .accessibilityIdentifier("settings.minimize-after-copy")
    }
}

struct MacQuickCopySettings: View {
    @AppStorage(MacClipboardPreference.showsQuickCopyActions) private var showsQuickCopyActions = false

    var body: some View {
        Toggle("Show quick copy actions on Vault", isOn: $showsQuickCopyActions)
            .accessibilityIdentifier("settings.quick-copy")
    }
}
