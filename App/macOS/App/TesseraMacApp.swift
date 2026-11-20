import SwiftUI
import AppKit
import UIShared
import DesignSystem
import VaultRepository
import AppShared

@main
struct TesseraMacApp: App {
    @State private var startup = Result { try AppEnvironment(opening: .macOS) }
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage(OpenVaultPreferenceKey.theme) private var theme = OpenVaultTheme.system

    private func content(_ environment: AppEnvironment) -> some View {
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

    var body: some Scene {
        WindowGroup("OpenVault") {
            switch startup {
            case .success(let environment):
                content(environment)
            case .failure(let error):
                ContentUnavailableView {
                    Label("OpenVault", systemImage: "lock.trianglebadge.exclamationmark")
                } description: {
                    Text(error.localizedDescription)
                } actions: {
                    Button("重试") { startup = Result { try AppEnvironment(opening: .macOS) } }
                }
            }
        }
        .defaultSize(width: 1260, height: 780)
        .windowResizability(.contentMinSize)
        .commands {
            MacVaultSearchCommands()
            CommandMenu("保险库") {
                Button("锁定 OpenVault") {
                    if case .success(let environment) = startup {
                        Task { await environment.lock() }
                    }
                }
                .keyboardShortcut("l", modifiers: [.command, .shift])
            }
        }
        .onChange(of: scenePhase) { _, newPhase in
            guard case .success(let environment) = startup else { return }
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
            if case .success(let environment) = startup {
                MenuBarContent(auth: environment.auth, vault: environment.vault,
                               biometricsEnabled: environment.settings.biometricUnlockEnabled)
                    .preferredColorScheme(theme.colorScheme)
                    .id(environment.authStateGeneration)
            }
        }
        .menuBarExtraStyle(.window)
    }
}
