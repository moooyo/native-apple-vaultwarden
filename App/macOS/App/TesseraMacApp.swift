import SwiftUI
import UIShared

@main
struct TesseraMacApp: App {
    @NSApplicationDelegateAdaptor(MacClipboardTerminationDelegate.self) private var terminationDelegate
    @State private var startup = Result { try MacWindowSession(environment: AppEnvironment(opening: .macOS)) }
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage(SettingsPreference.showsMenuBar) private var showsMenuBar = true

    private var menuBarInsertion: Binding<Bool> {
        Binding(get: { showsMenuBar }, set: { visible in
            if showsMenuBar != visible { showsMenuBar = visible }
        })
    }

    var body: some Scene {
        WindowGroup("OpenVault", id: "vault", for: MacVaultWindowID.self) { _ in
            sceneContent { MacRootView(session: $0) }
        } defaultValue: { .workspace }
        .defaultSize(width: 1280, height: 800)
        .windowResizability(.contentMinSize)
        .commands {
            MacVaultCommands()
            MacItemCommands()
            SidebarCommands()
        }
        .onChange(of: scenePhase) { _, next in
            guard case .success(let session) = startup else { return }
            switch next {
            case .background: session.environment.handleEnterBackground()
            case .active: Task { await session.environment.handleBecomeActive(); await session.refresh() }
            default: break
            }
        }

        Window("登录 OpenVault", id: "login") {
            sceneContent { MacLoginWindow(session: $0) }
        }
        .defaultSize(MacLoginWindow.contentSize)
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentSize)
        .defaultLaunchBehavior(.suppressed)
        .restorationBehavior(.disabled)

        Settings {
            sceneContent { MacSettingsWindow(session: $0) }
        }
        .defaultSize(width: 720, height: 250)
        .windowToolbarStyle(.expanded)
        .windowToolbarLabelStyle(fixed: .titleAndIcon)
        .windowResizability(.contentSize)

        MenuBarExtra(isInserted: menuBarInsertion) {
            sceneContent { session in
                MenuBarContent(auth: session.environment.auth, vault: session.environment.vault, phase: session.phase,
                               biometricsEnabled: session.environment.settings.biometricUnlockEnabled,
                               dataRevision: session.environment.dataRevision &+ session.syncRevision,
                               onRefresh: session.refresh, onLock: session.lock)
                    .id(session.environment.authStateGeneration)
            }
        } label: {
            Label("OpenVault", image: "OpenVaultMenuBar")
        }
        .menuBarExtraStyle(.window)
    }

    @ViewBuilder private func sceneContent<Content: View>(@ViewBuilder _ content: (MacWindowSession) -> Content) -> some View {
        switch startup {
        case .success(let session):
            content(session)
                .onAppear { session.startMonitoring() }
        case .failure:
            ContentUnavailableView {
                Label("无法打开保险库", systemImage: "lock.trianglebadge.exclamationmark")
            } description: {
                Text("请检查本机钥匙串和保险库文件是否可用。")
            } actions: {
                Button("重试") { startup = Result { try MacWindowSession(environment: AppEnvironment(opening: .macOS)) } }
            }
        }
    }
}
