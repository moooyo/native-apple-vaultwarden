// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// RootView — the top-level iOS scene router. It switches between the login flow,
// the unlock screen, and the main tab UI based on the auth/unlock lifecycle.
//
// Auth/unlock state lives outside the view models in UIShared (those drive a single
// screen each), so this view keeps a small `Phase` of its own and asks `AuthService`
// whether the vault is unlocked on appear and after each login/unlock transition.

import SwiftUI
import UIShared
import DesignSystem
import VaultRepository

@available(iOS 27.0, *)
public struct RootView: View {
    /// The high-level screen the app should show.
    enum Phase: Equatable {
        case loading
        case login
        case unlock
        case main
    }

    /// The service container the app builds at launch (real repositories behind the
    /// VM-facing protocols). Injected so the App target owns construction.
    private let auth: AuthService
    private let vault: VaultService
    /// The persisted server URL, used to seed the login + settings screens.
    private let settings: SettingsModel

    @State private var phase: Phase = .loading
    @AppStorage(OpenVaultPreferenceKey.glassTint) private var glassTint = 0.68
    @AppStorage(OpenVaultPreferenceKey.theme) private var themeRawValue = OpenVaultTheme.system.rawValue

    public init(auth: AuthService, vault: VaultService, settings: SettingsModel) {
        self.auth = auth
        self.vault = vault
        self.settings = settings
    }

    public var body: some View {
        Group {
            switch phase {
            case .loading:
                VStack(spacing: Spacing.xl) {
                    OpenVaultMark(size: 72)
                    ProgressView("正在打开保险库…")
                        .controlSize(.large)
                        .foregroundStyle(Palette.secondaryText)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Palette.groupedBackground)
            case .login:
                LoginView(model: LoginModel(auth: auth, serverURL: settings.serverURL)) { serverURL in
                    settings.serverURL = serverURL
                    // After a successful login the vault is unlocked → go straight to main.
                    phase = .main
                }
            case .unlock:
                UnlockView(model: UnlockModel(auth: auth)) {
                    phase = .main
                }
            case .main:
                MainTabView(auth: auth, vault: vault, settings: settings) {
                    // The Settings "Lock now" / "Log out" actions ask us to re-route.
                    await resolvePhase(afterLogout: true)
                }
            }
        }
        .openVaultGlassTint(glassTint)
        .preferredColorScheme(OpenVaultTheme(rawValue: themeRawValue)?.colorScheme)
        .task { await resolvePhase() }
        .task { await monitorLockState() }
    }

    /// Decide the initial phase: if there's no session we show login; if there is a
    /// session but the vault is locked we show unlock; otherwise main.
    ///
    /// `afterLogout` forces a re-read (the Settings screen may have locked or logged out).
    private func resolvePhase(afterLogout: Bool = false) async {
        if await auth.isUnlocked() {
            phase = .main
        } else if afterLogout {
            // Locked but possibly still signed in — try unlock; the unlock screen offers
            // a path back to login if the master password fails repeatedly.
            phase = .unlock
        } else {
            // Cold start with no unlocked vault. We don't have a "has session" probe on
            // the VM-facing protocol, so default to login; an already-signed-in account
            // will be handled by the App target seeding `.unlock` instead. M1 keeps this
            // simple: fresh launch → login.
            phase = .login
        }
    }

    private func monitorLockState() async {
        while !Task.isCancelled {
            try? await Task.sleep(for: .seconds(1))
            guard phase == .main else { continue }
            if !(await auth.isUnlocked()) {
                // Replacing MainTabView promptly releases decrypted list/detail state.
                await resolvePhase(afterLogout: true)
            }
        }
    }
}
