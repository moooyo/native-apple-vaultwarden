import AppKit
import DesignSystem
import SwiftUI

enum MacAppPreference {
    static let keepsRunningInBackground = "openvault.mac.keepsRunningInBackground"
    static let defaultKeepsRunningInBackground = true
}

@MainActor
final class MacApplicationDelegate: NSObject, NSApplicationDelegate {
    private let defaults: UserDefaults

    override convenience init() { self.init(defaults: .standard) }

    init(defaults: UserDefaults) {
        self.defaults = defaults
        super.init()
    }

    func applicationWillFinishLaunching(_ notification: Notification) {
        guard let application = notification.object as? NSApplication else { return }
        let theme = defaults.string(forKey: OpenVaultPreferenceKey.theme).flatMap(OpenVaultTheme.init(rawValue:)) ?? .system
        MacAppAppearance.apply(theme, to: application)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        let keepsRunning = defaults.object(forKey: MacAppPreference.keepsRunningInBackground) as? Bool
            ?? MacAppPreference.defaultKeepsRunningInBackground
        return !keepsRunning
    }

    func applicationWillTerminate(_ notification: Notification) { MacClipboard.shared.clearOwnedCopy() }
}

struct MacAppAppearance: ViewModifier {
    @AppStorage(OpenVaultPreferenceKey.theme) private var theme = OpenVaultTheme.system

    func body(content: Content) -> some View {
        content
            .preferredColorScheme(theme.colorScheme)
            .onChange(of: theme, initial: true) { _, value in Self.apply(value, to: NSApplication.shared) }
    }

    static func apply(_ theme: OpenVaultTheme, to application: NSApplication) {
        let name: NSAppearance.Name? = switch theme {
        case .system: nil
        case .light: .aqua
        case .dark: .darkAqua
        }
        guard application.appearance?.name != name else { return }
        application.appearance = name.flatMap(NSAppearance.init(named:))
    }
}
