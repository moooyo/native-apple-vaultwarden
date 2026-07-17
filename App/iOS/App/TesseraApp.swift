import SwiftUI
import BackgroundTasks
import UIShared
import DesignSystem
import VaultRepository
import AppShared

@available(iOS 27.0, *)
@main
struct TesseraApp: App {
    @State private var environment = AppEnvironment(platform: .iOS)
    @Environment(\.scenePhase) private var scenePhase
    @State private var obscuresSensitiveContent = false

    init() {
        AppEnvironment.registerBackgroundRefreshHandler(identifier: BackgroundIdentifiers.sync)
    }

    var body: some Scene {
        WindowGroup {
            Group {
                if environment.didSeedSession {
                    RootView(
                        auth: environment.auth,
                        vault: environment.vault,
                        settings: environment.settings,
                        dataRevision: environment.dataRevision
                    )
                    .id(environment.authStateGeneration)
                } else {
                    VStack(spacing: Spacing.xl) {
                        OpenVaultMark(size: 72)
                        ProgressView("正在恢复保险库…")
                            .controlSize(.large)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(Palette.groupedBackground)
                }
            }
            .task {
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
            .overlay {
                if obscuresSensitiveContent {
                    OpenVaultPrivacyShield()
                        .transition(.opacity)
                }
            }
        }
        .onChange(of: scenePhase) { _, newPhase in
            switch newPhase {
            case .background:
                obscuresSensitiveContent = true
                environment.handleEnterBackground()
                environment.scheduleBackgroundRefresh(identifier: BackgroundIdentifiers.sync)
            case .active:
                Task {
                    await environment.handleBecomeActive()
                    guard scenePhase == .active else { return }
                    obscuresSensitiveContent = false
                }
            case .inactive:
                obscuresSensitiveContent = true
            @unknown default:
                obscuresSensitiveContent = true
            }
        }
    }
}

@available(iOS 27.0, *)
private struct OpenVaultPrivacyShield: View {
    var body: some View {
        ZStack {
            Palette.groupedBackground.ignoresSafeArea()
            VStack(spacing: 14) {
                OpenVaultMark(size: 64)
                Label("OpenVault 已隐藏", systemImage: "lock.fill")
                    .font(.headline)
                    .foregroundStyle(Palette.secondaryText)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("OpenVault 内容已隐藏")
    }
}

enum BackgroundIdentifiers {
    static let sync = "dev.moooyo.tessera.sync"
}
