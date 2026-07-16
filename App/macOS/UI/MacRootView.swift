// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// MacRootView — the top-level macOS window. Routes between login, unlock, and the main
// three-column vault UI based on the auth/unlock lifecycle (mirrors the iOS RootView).
//
// The main UI is a three-column `NavigationSplitView` (categories/folders sidebar |
// item list | detail). Standard split-view chrome (sidebar, toolbars) gets Liquid Glass
// automatically on recompile.

import SwiftUI
import UIShared
import DesignSystem
import VaultRepository

@available(macOS 26.0, *)
public struct MacRootView: View {
    enum Phase: Equatable { case loading, login, unlock, main }

    private let auth: AuthService
    private let vault: VaultService
    private let settings: SettingsModel
    private let dataRevision: UInt64

    @State private var phase: Phase = .loading

    public init(auth: AuthService, vault: VaultService, settings: SettingsModel,
                dataRevision: UInt64 = 0) {
        self.auth = auth
        self.vault = vault
        self.settings = settings
        self.dataRevision = dataRevision
    }

    public var body: some View {
        Group {
            switch phase {
            case .loading:
                ProgressView()
                    .controlSize(.large)
                    .frame(minWidth: 480, minHeight: 320)
            case .login:
                MacLoginView(model: LoginModel(auth: auth, serverURL: settings.serverURL)) { serverURL in
                    settings.serverURL = serverURL
                    phase = .main
                }
                .frame(minWidth: 420, minHeight: 360)
            case .unlock:
                MacUnlockView(model: UnlockModel(auth: auth)) {
                    phase = .main
                }
                .frame(minWidth: 420, minHeight: 320)
            case .main:
                MacMainView(auth: auth, vault: vault, settings: settings,
                            dataRevision: dataRevision) {
                    await resolvePhase()
                }
                .frame(minWidth: 900, minHeight: 560)
            }
        }
        .task { await resolvePhase() }
    }

    private func resolvePhase() async {
        if await auth.isUnlocked() {
            phase = .main
        } else if await auth.hasSession() {
            phase = .unlock
        } else {
            phase = .login
        }
    }
}
