// Xcode-only target. Not part of the SPM build.
//
// TesseraMacApp — the macOS `@main` entry point.
//
// Two scenes:
//   * the main `WindowGroup { MacRootView(...) }` (three-column vault UI), and
//   * a `MenuBarExtra { MenuBarContent(...) }` for quick unlock / search / copy.
//
// Same `AppEnvironment` DI graph as iOS (VaultStore opened in the shared App Group container).
// Periodic sync uses `NSBackgroundActivityScheduler` (no BGTaskScheduler on macOS), and the
// vault auto-locks on resign-active / when the `AutoLockTimeout` elapses.

import SwiftUI
import AppKit
import UIShared
import VaultRepository
import AppShared

@available(macOS 26.0, *)
@main
struct TesseraMacApp: App {
    @State private var environment = AppEnvironment(platform: .macOS)

    /// Observes app activation so we can auto-lock on resign-active / timeout.
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            Group {
                if environment.didSeedSession {
                    MacRootView(auth: environment.auth,
                                vault: environment.vault,
                                settings: environment.settings,
                                dataRevision: environment.dataRevision)
                        .id(environment.authStateGeneration)
                } else {
                    ProgressView()
                        .frame(minWidth: 480, minHeight: 320)
                }
            }
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

        MenuBarExtra("Tessera", systemImage: "lock.shield") {
            MenuBarContent(auth: environment.auth, vault: environment.vault)
                .id(environment.authStateGeneration)
        }
        .menuBarExtraStyle(.window)
    }
}
