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

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
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
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
            case .login:
                MacLoginView(model: LoginModel(auth: auth, serverURL: settings.serverURL)) { serverURL in
                    settings.serverURL = serverURL
                    show(.main)
                }
            case .unlock:
                MacUnlockView(model: UnlockModel(auth: auth),
                              biometricsEnabled: settings.biometricUnlockEnabled) {
                    show(.main)
                }
            case .main:
                MacMainView(auth: auth, vault: vault, settings: settings,
                            dataRevision: dataRevision) {
                    await resolvePhase()
                }
            }
        }
        .frame(minWidth: 960, minHeight: 620)
        .task { await resolvePhase() }
        .task { await monitorLockState() }
    }

    private func resolvePhase() async {
        let unlocked = await auth.isUnlocked()
        let hasSession = unlocked ? true : await auth.hasSession()
        show(unlocked ? .main : (hasSession ? .unlock : .login))
    }

    private func monitorLockState() async {
        while !Task.isCancelled {
            try? await Task.sleep(for: .milliseconds(500))
            let unlocked = await auth.isUnlocked()
            let hasSession = unlocked ? true : await auth.hasSession()
            let desired: Phase = unlocked ? .main : (hasSession ? .unlock : .login)
            show(desired)
        }
    }

    private func show(_ newPhase: Phase) {
        guard phase != newPhase else { return }
        // Never animate the previous vault contents underneath a locked screen.
        let animate = newPhase == .main && !reduceMotion
        withAnimation(animate ? .smooth(duration: 0.22) : nil) { phase = newPhase }
    }
}
