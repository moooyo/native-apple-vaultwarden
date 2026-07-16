// Xcode-only target. Not part of the SPM build.
//
// TesseraApp — the iOS `@main` entry point.
//
// Responsibilities (blueprint §G / design spec §5.9):
//   * Build the production `ServiceContainer` (real `APIClient` + `VaultStore` opened in
//     the App Group container + shared `KeyVault` + `KeychainBridge` + repositories), wrapped
//     in the VM-facing `AuthService` / `VaultService` adapters that `RootView` consumes.
//   * Register the `BGAppRefreshTask` (id declared in Info-iOS.plist
//     `BGTaskSchedulerPermittedIdentifiers`) whose handler runs `SyncEngine.fullSync` +
//     `flushOutbox`.
//   * Observe the scene phase and auto-lock the vault (KeyVault + the write-path encryptor)
//     on background / when the `AutoLockTimeout` elapses.
//   * Seed an already-signed-in session at launch (the App layer knows the persisted session,
//     `RootView` only knows "is the vault unlocked").
//
// The heavy DI wiring lives in `AppEnvironment` (shared by the iOS + macOS apps) so this
// file stays a thin shell.

import SwiftUI
import BackgroundTasks
import UIShared
import VaultRepository
import AppShared

@available(iOS 26.0, *)
@main
struct TesseraApp: App {
    /// The composed service graph + VM-facing adapters, built once at launch.
    @State private var environment = AppEnvironment(platform: .iOS)

    /// Tracks the moment we resigned active so we can apply the auto-lock timeout on return.
    @Environment(\.scenePhase) private var scenePhase

    init() {
        // Register the BGAppRefreshTask handler BEFORE the app finishes launching (UIKit
        // requirement). The handler reaches back into the environment to run the sync.
        AppEnvironment.registerBackgroundRefreshHandler(identifier: BackgroundIdentifiers.sync)
    }

    var body: some Scene {
        WindowGroup {
            Group {
                if environment.didSeedSession {
                    RootView(auth: environment.auth,
                             vault: environment.vault,
                             settings: environment.settings,
                             dataRevision: environment.dataRevision)
                        .id(environment.authStateGeneration)
                } else {
                    ProgressView()
                }
            }
            .task {
                // RootView is inserted only after restoration, avoiding an initial-route race.
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
        .onChange(of: scenePhase) { _, newPhase in
            switch newPhase {
            case .background:
                environment.handleEnterBackground()
                environment.scheduleBackgroundRefresh(identifier: BackgroundIdentifiers.sync)
            case .active:
                Task { await environment.handleBecomeActive() }
            case .inactive:
                break
            @unknown default:
                break
            }
        }
    }
}

/// Background-task identifiers. Must match Info-iOS.plist `BGTaskSchedulerPermittedIdentifiers`.
enum BackgroundIdentifiers {
    static let sync = "dev.moooyo.tessera.sync"
}
