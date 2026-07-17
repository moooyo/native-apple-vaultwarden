import SwiftUI
import AppKit
import UIShared
import DesignSystem
import VaultRepository
import AppShared

@available(macOS 27.0, *)
@main
struct TesseraMacApp: App {
    @State private var environment = AppEnvironment(platform: .macOS)
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage(OpenVaultPreferenceKey.glassTint) private var glassTint = 0.68
    private let selectedColorScheme: ColorScheme? = .dark

    var body: some Scene {
        WindowGroup("OpenVault") {
            MacRootView(
                auth: environment.auth,
                vault: environment.vault,
                settings: environment.settings
            )
            .openVaultGlassTint(glassTint)
            .preferredColorScheme(selectedColorScheme)
            .onChange(of: environment.settings.serverURL) { _, _ in environment.persistSettings() }
            .onChange(of: environment.settings.autoLockTimeout) { _, _ in environment.persistSettings() }
            .onChange(of: environment.settings.biometricUnlockEnabled) { _, _ in environment.persistSettings() }
            .task {
                await environment.seedSessionIfPresent()
                environment.startMacBackgroundActivity()
            }
        }
        .defaultSize(width: 1260, height: 780)
        .windowResizability(.contentMinSize)
        .commands {
            CommandMenu("保险库") {
                Button("锁定 OpenVault") {
                    Task { await environment.lock() }
                }
                .keyboardShortcut("l", modifiers: [.command, .shift])
            }
        }
        .onChange(of: scenePhase) { _, newPhase in
            switch newPhase {
            case .background:
                environment.handleEnterBackground()
            case .active:
                Task { await environment.handleBecomeActive() }
            default:
                break
            }
        }

        MenuBarExtra("OpenVault", systemImage: "lock.shield") {
            MenuBarContent(auth: environment.auth, vault: environment.vault)
                .openVaultGlassTint(glassTint)
                .preferredColorScheme(selectedColorScheme)
        }
        .menuBarExtraStyle(.window)
    }
}
