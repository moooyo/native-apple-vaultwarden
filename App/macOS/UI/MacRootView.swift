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
                MacMainView(auth: auth, vault: vault, settings: settings,
                            dataRevision: dataRevision) {
                    await resolvePhase()
                }
            }
        }
        .frame(minWidth: 960, minHeight: 620)
        .background(MacOpenVaultStyle.window)
        .task { await resolvePhase() }
        .task { await monitorLockState() }
    }

    private func resolvePhase() async {
        let unlocked = await auth.isUnlocked()
        let hasSession = unlocked ? true : await auth.hasSession()
        withAnimation(.smooth(duration: 0.22)) {
            if unlocked {
                phase = .main
            } else if hasSession {
                phase = .unlock
            } else {
                phase = .login
            }
        }
    }

    private func monitorLockState() async {
        while !Task.isCancelled {
            try? await Task.sleep(for: .milliseconds(500))
            let unlocked = await auth.isUnlocked()
            let hasSession = unlocked ? true : await auth.hasSession()
            let desired: Phase = unlocked ? .main : (hasSession ? .unlock : .login)
            if phase != desired {
                withAnimation(.smooth(duration: 0.22)) { phase = desired }
            }
        }
    }
}
