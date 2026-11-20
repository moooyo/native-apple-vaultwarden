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
    @AppStorage(OpenVaultPreferenceKey.theme) private var theme = OpenVaultTheme.system

    var body: some Scene {
        WindowGroup("OpenVault") {
            Group {
                if environment.didSeedSession {
                    MacRootView(auth: environment.auth,
                                vault: environment.vault,
                                settings: environment.settings,
                                dataRevision: environment.dataRevision)
                        .id(environment.authStateGeneration)
                } else {
                    ZStack {
                        OpenVaultLockBackground()
                        VStack(spacing: 14) {
                            OpenVaultMark(size: 58)
                            ProgressView().controlSize(.small)
                            Text("正在恢复 OpenVault 会话…")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .frame(minWidth: 960, minHeight: 620)
                }
            }
            .preferredColorScheme(theme.colorScheme)
            .task {
                environment.startMacBackgroundActivity()
                await environment.seedSessionIfPresent()
            }
            .onChange(of: environment.settings.serverURL) { _, _ in
                environment.persistSettings()
            }
            .onChange(of: environment.settings.autoLockTimeout) { _, _ in
                environment.persistSettings()
            }
            .onChange(of: environment.settings.biometricUnlockEnabled) { _, _ in
                environment.handleBiometricSettingChanged()
            }
        }
        .defaultSize(width: 1260, height: 780)
        .windowResizability(.contentMinSize)
        .commands {
            MacVaultSearchCommands()
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
            MenuBarContent(auth: environment.auth, vault: environment.vault,
                           biometricsEnabled: environment.settings.biometricUnlockEnabled)
                .preferredColorScheme(theme.colorScheme)
                .id(environment.authStateGeneration)
        }
        .menuBarExtraStyle(.window)
    }
}
