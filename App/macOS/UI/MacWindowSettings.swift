import AppKit
import DesignSystem
import ServiceManagement
import SwiftUI

struct MacKeepRunningSetting: View {
    @AppStorage(MacAppPreference.keepsRunningInBackground) private var keepsRunning = MacAppPreference.defaultKeepsRunningInBackground

    var body: some View {
        Toggle("Keep OpenVault running in the background", isOn: $keepsRunning)
            .accessibilityIdentifier("settings.keep-running")
            .help("Closing the last window keeps OpenVault running when enabled. Quit OpenVault to exit.")
    }
}

struct MacThemeSetting: View {
    @AppStorage(OpenVaultPreferenceKey.theme) private var theme = OpenVaultTheme.system

    var body: some View {
        Picker("Theme", selection: $theme) {
            Text("System").tag(OpenVaultTheme.system)
            Text("Light").tag(OpenVaultTheme.light)
            Text("Dark").tag(OpenVaultTheme.dark)
        }
        .accessibilityIdentifier("settings.theme")
    }
}

enum MacLoginItemStatus: Equatable {
    case notRegistered, enabled, requiresApproval, unavailable

    var isRegistered: Bool { self == .enabled || self == .requiresApproval }
}

@MainActor @Observable
final class MacLoginItemSettings {
    private(set) var status = MacLoginItemStatus.unavailable
    var showingError = false

    func refresh(using service: MacLoginItemService) { status = service.status() }

    func updateRegistration(_ enabled: Bool, using service: MacLoginItemService) {
        refresh(using: service)
        guard status != .unavailable, status.isRegistered != enabled else { return }
        let changed = (try? service.updateRegistration(enabled)) != nil
        refresh(using: service)
        showingError = !changed && (status == .unavailable || status.isRegistered != enabled)
    }
}

struct MacLoginItemService: Sendable {
    let status: @MainActor @Sendable () -> MacLoginItemStatus
    let updateRegistration: @MainActor @Sendable (Bool) throws -> Void
    let openSettings: @MainActor @Sendable () -> Void

    static let unavailable = Self(status: { .unavailable }, updateRegistration: { _ in }, openSettings: {})

    static let live: Self = {
        #if OPENVAULT_LOCAL_FIXTURE
        .unavailable
        #else
        Self(status: {
            switch SMAppService.mainApp.status {
            case .notRegistered: .notRegistered
            case .enabled: .enabled
            case .requiresApproval: .requiresApproval
            case .notFound: .unavailable
            @unknown default: .unavailable
            }
        }, updateRegistration: { enabled in
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
        }, openSettings: { SMAppService.openSystemSettingsLoginItems() })
        #endif
    }()
}

extension EnvironmentValues {
    @Entry var macLoginItemService = MacLoginItemService.unavailable
}

struct MacLaunchAtLoginSetting: View {
    @Environment(\.macLoginItemService) private var service
    @Environment(\.appearsActive) private var appearsActive
    @State private var settings = MacLoginItemSettings()

    var body: some View {
        @Bindable var settings = settings
        Group {
            Toggle("Launch at login", isOn: Binding(
                get: { settings.status.isRegistered },
                set: { settings.updateRegistration($0, using: service) }
            ))
                .disabled(settings.status == .unavailable)
                .accessibilityIdentifier("settings.launch-at-login")
                .onChange(of: appearsActive, initial: true) { _, _ in settings.refresh(using: service) }
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                    settings.refresh(using: service)
                }
                .alert("Couldn't change launch at login", isPresented: $settings.showingError) {
                    Button("OK", role: .cancel) {}
                } message: {
                    Text("Check Login Items in System Settings and try again.")
                }
            if settings.status == .requiresApproval {
                HStack {
                    Text("Allow OpenVault in System Settings to finish setting up launch at login.")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Open Login Items…", action: service.openSettings)
                        .accessibilityIdentifier("settings.login-items")
                }
            } else if settings.status == .unavailable {
                Text("Launch at login is unavailable for this copy of OpenVault.")
                    .foregroundStyle(.secondary)
            }
        }
    }
}
