import AppKit
import Networking
import SwiftUI
import DesignSystem
import UIShared
import VaultRepository

@MainActor @Observable
final class MacWindowSession {
    let environment: AppEnvironment
    @ObservationIgnored let sshAgent: MacSSHAgentController
    private(set) var syncModel: SyncStatusModel
    private(set) var syncRevision: UInt64 = 0
    private(set) var websiteIcons: MacWebsiteIcons?
    private(set) var contentGeneration: UInt64 = 0
    private var refreshRequest: UInt64 = 0
    private var presentedPhase: MacVaultPhase = .loading
    private var presentedAuthGeneration: UInt64 = 0
    private(set) var workspaceLease: AccountSessionLease?
    private var websiteIconServer: ServerEnvironment?
    private var showsWebsiteIcons = false
    @ObservationIgnored private var monitorTask: Task<Void, Never>?

    var phase: MacVaultPhase {
        presentedPhase == .main && presentedAuthGeneration != environment.authStateGeneration ? .unlock : presentedPhase
    }

    init(environment: AppEnvironment) {
        self.environment = environment
        sshAgent = MacSSHAgentController(auth: environment.auth, vault: environment.vault, beforeAccess: { [weak environment] in
            await environment?.enforceMacTimeoutBeforeAccess()
        })
        syncModel = SyncStatusModel(vault: environment.vault)
    }

    func refresh() async {
        guard environment.didSeedSession else { return }
        refreshRequest &+= 1
        let request = refreshRequest
        if environment.sessionRestoreFailed {
            presentedPhase = .loading
            sshAgent.sessionDidChange(to: nil)
            return
        }
        let authGeneration = environment.authStateGeneration
        let lease = await environment.auth.transferSession()
        let server = await environment.authenticatedServerURL()
        if let lease {
            guard server != nil, await environment.auth.transferSession() == lease else { return }
        }
        let authenticatedLease = await environment.currentMacTimeoutLease()
        guard request == refreshRequest, authGeneration == environment.authStateGeneration,
              lease == nil || lease == authenticatedLease else { return }
        environment.updateMacTimeoutLease(lease, authenticated: authenticatedLease)
        let next: MacVaultPhase = lease != nil ? .main : server != nil ? .unlock : .login
        sshAgent.sessionDidChange(to: lease)
        let workspaceChanged = lease != workspaceLease
        if (next != presentedPhase || workspaceChanged), let server {
            if environment.settings.serverURL != server {
                environment.settings.serverURL = server
                environment.persistSettings()
            }
            if next == .main {
                if workspaceChanged { resetWebsiteIcons() }
                websiteIconServer = ServerEnvironment(string: server)
            }
        }
        if next != .main {
            websiteIconServer = nil
            resetWebsiteIcons()
        }
        if workspaceChanged || (next != presentedPhase && (next == .main || presentedPhase == .main)) {
            workspaceLease = lease
            contentGeneration &+= 1
            syncModel = SyncStatusModel(vault: environment.vault, onSuccess: { [weak self] in
                await self?.didSync()
            })
        }
        updateWebsiteIcons()
        presentedAuthGeneration = authGeneration
        if presentedPhase != next { presentedPhase = next }
    }

    func setWebsiteIconPreference(_ enabled: Bool) {
        guard showsWebsiteIcons != enabled else { return }
        showsWebsiteIcons = enabled
        updateWebsiteIcons()
    }

    private func updateWebsiteIcons() {
        guard showsWebsiteIcons, environment.allowsWebsiteIconRequests, let websiteIconServer, let workspaceLease else {
            resetWebsiteIcons()
            return
        }
        if websiteIcons == nil {
            let auth = environment.auth
            websiteIcons = MacWebsiteIcons(server: websiteIconServer) { [weak self] in
                guard await auth.transferSession() == workspaceLease else { return false }
                return await self?.allowsWebsiteIcons(for: workspaceLease) == true
            }
        }
    }

    private func allowsWebsiteIcons(for lease: AccountSessionLease) -> Bool {
        showsWebsiteIcons && workspaceLease == lease
    }

    private func resetWebsiteIcons() {
        guard let websiteIcons else { return }
        websiteIcons.invalidate()
        self.websiteIcons = nil
    }

    private func didSync() { syncRevision &+= 1 }

    func startMonitoring() {
        guard monitorTask == nil else { return }
        sshAgent.start()
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
        sshAgent.sessionDidChange(to: nil)
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
                if session.environment.sessionRestoreFailed {
                    ContentUnavailableView {
                        Label("Could Not Restore the Session", systemImage: "exclamationmark.triangle")
                    } description: {
                        Text("The encrypted vault was kept unchanged.")
                    } actions: {
                        Button("Retry") { Task { await session.environment.retrySessionRestore(); await session.refresh() } }
                    }
                } else {
                    VStack(spacing: 14) {
                        OpenVaultMark(size: 58)
                        ProgressView("Opening OpenVault…").controlSize(.small)
                    }
                }
            case .unlock:
                MacUnlockView(model: UnlockModel(auth: session.environment.auth),
                              biometricsEnabled: session.environment.settings.biometricUnlockEnabled,
                              timeoutSignOutFailed: session.environment.macTimeoutSignOutFailed,
                              onLoggedOut: { Task { await session.refresh() } }) {
                    Task { await session.refresh() }
                }
            case .main:
                MacMainView(auth: session.environment.auth, vault: session.environment.vault, syncModel: session.syncModel,
                            dataRevision: session.environment.dataRevision &+ session.syncRevision,
                            workspaceLease: session.workspaceLease, onLock: session.lock)
                    .id(session.contentGeneration)
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
    static let contentSize = NSWindow.contentRect(
        forFrameRect: CGRect(x: 0, y: 0, width: 560, height: 500),
        styleMask: [.titled, .closable, .miniaturizable]
    ).size

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
                ProgressView("Opening OpenVault…")
            }
        }
        .frame(width: Self.contentSize.width, height: Self.contentSize.height)
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
    @State private var signOutFailed = false

    var body: some View {
        MacSettingsView(auth: session.environment.auth, syncModel: session.syncModel, settings: session.environment.settings,
                        timeoutSettings: session.environment.macSessionTimeoutSettings, isVaultUnlocked: session.phase == .main,
                        onSync: {}, onAuthChange: {
                            await session.refresh()
                            openVault()
                        }, onLock: session.lock, onSignOutFailure: {
                            signOutFailed = true
                            Task { await session.refresh() }
                        }, onOpenVault: openVault)
        .id(session.contentGeneration)
        .onChange(of: session.environment.settings.biometricUnlockEnabled) { session.environment.handleBiometricSettingChanged() }
        .alert("Could Not Sign Out", isPresented: $signOutFailed) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("OpenVault could not remove the local session. Try again.")
        }
    }

    private func openVault() {
        if session.phase == .login { openWindow(id: "login") }
        else { openWindow(id: "vault", value: MacVaultWindowID.workspace) }
    }
}
