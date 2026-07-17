import SwiftUI
import UIShared
import DesignSystem
import VaultRepository

@available(macOS 27.0, *)
public struct MacRootView: View {
    enum Phase: Equatable { case loading, login, unlock, main }

    private let auth: AuthService
    private let vault: VaultService
    private let settings: SettingsModel

    @State private var phase: Phase = .loading

    public init(auth: AuthService, vault: VaultService, settings: SettingsModel) {
        self.auth = auth
        self.vault = vault
        self.settings = settings
    }

    public var body: some View {
        Group {
            switch phase {
            case .loading:
                ZStack {
                    OpenVaultLockBackground()
                    VStack(spacing: 14) {
                        OpenVaultMark(size: 58)
                        ProgressView()
                            .controlSize(.small)
                        Text("正在打开 OpenVault…")
                            .font(.system(size: 12.5))
                            .foregroundStyle(.white.opacity(0.46))
                    }
                }
            case .login:
                MacLoginView(model: LoginModel(auth: auth, serverURL: settings.serverURL)) { serverURL in
                    settings.serverURL = serverURL
                    withAnimation(.smooth(duration: 0.28)) { phase = .main }
                }
            case .unlock:
                MacUnlockView(model: UnlockModel(auth: auth)) {
                    withAnimation(.smooth(duration: 0.28)) { phase = .main }
                }
            case .main:
                MacMainView(auth: auth, vault: vault, settings: settings) {
                    await resolvePhase(afterLock: true)
                }
            }
        }
        .frame(minWidth: 960, minHeight: 620)
        .background(MacOpenVaultStyle.window)
        .task { await resolvePhase() }
        .task { await monitorLockState() }
    }

    private func resolvePhase(afterLock: Bool = false) async {
        let unlocked = await auth.isUnlocked()
        withAnimation(.smooth(duration: 0.22)) {
            if unlocked {
                phase = .main
            } else if afterLock {
                phase = .unlock
            } else if phase == .main {
                phase = .unlock
            } else {
                // The current AuthService does not expose a persisted-session probe.
                // A cold launch therefore stays on login rather than pretending unlock can work.
                phase = .login
            }
        }
    }

    private func monitorLockState() async {
        while !Task.isCancelled {
            try? await Task.sleep(for: .seconds(1))
            guard phase == .main else { continue }
            if !(await auth.isUnlocked()) {
                // Replacing MacMainView releases decrypted list/detail values held by UI state.
                await resolvePhase(afterLock: true)
            }
        }
    }
}
