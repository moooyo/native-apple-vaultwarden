import SwiftUI
import DesignSystem
import UIShared

@MainActor @Observable
final class MacWindowSession {
    let environment: AppEnvironment
    private(set) var phase: MacVaultPhase = .loading
    private(set) var syncModel: SyncStatusModel
    private(set) var syncRevision: UInt64 = 0
    private var refreshRequest: UInt64 = 0
    @ObservationIgnored private var monitorTask: Task<Void, Never>?

    init(environment: AppEnvironment) {
        self.environment = environment
        syncModel = SyncStatusModel(vault: environment.vault)
    }

    func refresh() async {
        guard environment.didSeedSession else { return }
        refreshRequest &+= 1
        let request = refreshRequest
        let unlocked = await environment.auth.isUnlocked()
        let hasSession = unlocked ? true : await environment.auth.hasSession()
        guard request == refreshRequest else { return }
        let next: MacVaultPhase = unlocked ? .main : hasSession ? .unlock : .login
        if next != phase && (next == .main || next == .unlock) {
            guard let server = await environment.authenticatedServerURL(), request == refreshRequest else { return }
            if environment.settings.serverURL != server {
                environment.settings.serverURL = server
                environment.persistSettings()
            }
        }
        if next != phase && (next == .main || phase == .main) {
            syncModel = SyncStatusModel(vault: environment.vault, onSuccess: { [weak self] in
                await self?.didSync()
            })
        }
        if phase != next { phase = next }
    }

    private func didSync() { syncRevision &+= 1 }

    func startMonitoring() {
        guard monitorTask == nil else { return }
        environment.startMacBackgroundActivity()
        monitorTask = Task { [weak self] in
            await self?.environment.seedSessionIfPresent()
            while !Task.isCancelled {
                guard self != nil else { return }
                await self?.refresh()
                do { try await Task.sleep(for: .milliseconds(500)) } catch { return }
            }
        }
    }

    deinit { monitorTask?.cancel() }

    func lock() async {
        await environment.lock()
        await refresh()
    }
}

struct MacRootView: View {
    let session: MacWindowSession
    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismissWindow) private var dismissWindow

    var body: some View {
        Group {
            switch session.phase {
            case .loading, .login:
                VStack(spacing: 14) {
                    OpenVaultMark(size: 58)
                    ProgressView("正在打开 OpenVault…").controlSize(.small)
                }
            case .unlock:
                MacUnlockView(model: UnlockModel(auth: session.environment.auth),
                              biometricsEnabled: session.environment.settings.biometricUnlockEnabled,
                              onLoggedOut: { Task { await session.refresh() } }) {
                    Task { await session.refresh() }
                }
            case .main:
                MacMainView(auth: session.environment.auth, vault: session.environment.vault, syncModel: session.syncModel,
                            dataRevision: session.environment.dataRevision &+ session.syncRevision, onLock: session.lock)
                    .id(session.environment.authStateGeneration)
            }
        }
        .frame(minWidth: 850, minHeight: 560)
        .onChange(of: session.phase, initial: true) { _, phase in
            if phase == .login {
                openWindow(id: "login")
                dismissWindow(id: "vault")
            }
        }
    }
}

struct MacLoginWindow: View {
    let session: MacWindowSession
    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismissWindow) private var dismissWindow

    var body: some View {
        Group {
            if session.phase == .login {
                MacLoginView(model: LoginModel(auth: session.environment.auth, serverURL: session.environment.settings.serverURL)) { _ in
                    Task { await session.refresh() }
                }
            } else {
                ProgressView("正在打开 OpenVault…")
            }
        }
        .frame(width: 560, height: 500)
        .onChange(of: session.phase, initial: true) { _, phase in
            if phase == .main || phase == .unlock {
                openWindow(id: "vault", value: MacVaultWindowID.workspace)
                dismissWindow(id: "login")
            }
        }
    }
}

struct MacSettingsWindow: View {
    let session: MacWindowSession
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if session.phase == .main {
            MacSettingsView(auth: session.environment.auth, syncModel: session.syncModel, settings: session.environment.settings,
                            onSync: {}, onAuthChange: {
                                await session.refresh()
                                openWindow(id: "vault", value: MacVaultWindowID.workspace)
                            })
                .id(session.environment.authStateGeneration)
                .onChange(of: session.environment.settings.autoLockTimeout) { session.environment.persistSettings() }
                .onChange(of: session.environment.settings.biometricUnlockEnabled) { session.environment.handleBiometricSettingChanged() }
        } else {
            ContentUnavailableView {
                Label("保险库未解锁", systemImage: "lock")
            } description: {
                Text("打开 OpenVault 后即可更改设置。")
            } actions: {
                Button("打开 OpenVault") { openWindow(id: "vault", value: MacVaultWindowID.workspace) }
            }
            .frame(width: 720, height: 330)
        }
    }
}
