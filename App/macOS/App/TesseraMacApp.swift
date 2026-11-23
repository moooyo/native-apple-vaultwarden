import SwiftUI
import UIShared

@main
struct TesseraMacApp: App {
    @NSApplicationDelegateAdaptor(MacApplicationDelegate.self) private var applicationDelegate
    @State private var startup = Result { try MacWindowSession(environment: AppEnvironment(opening: .macOS)) }
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage(SettingsPreference.showsMenuBar) private var showsMenuBar = true
    @AppStorage(SettingsPreference.showsWebsiteIcons) private var showsWebsiteIcons = SettingsPreference.defaultShowsWebsiteIcons

    private var menuBarInsertion: Binding<Bool> {
        Binding(get: { showsMenuBar }, set: { visible in
            if showsMenuBar != visible { showsMenuBar = visible }
        })
    }

    var body: some Scene {
        WindowGroup("OpenVault", id: "vault", for: MacVaultWindowID.self) { _ in
            sceneContent { MacRootView(session: $0) }
        } defaultValue: { .workspace }
        .defaultLaunchBehavior(.presented)
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

        Window(MacLocalization.text("Sign in to OpenVault"), id: "login") {
            sceneContent { MacLoginWindow(session: $0) }
        }
        .defaultSize(MacLoginWindow.contentSize)
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentSize)
        .defaultLaunchBehavior(.suppressed)
        .restorationBehavior(.disabled)

        Settings {
            sceneContent { MacSettingsWindow(session: $0) }
                .frame(width: 720)
                .frame(minHeight: 330, idealHeight: 465, maxHeight: .infinity)
                .windowResizeBehavior(.enabled)
        }
        .defaultSize(width: 720, height: 465)
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

    private func sceneContent<Content: View>(@ViewBuilder _ content: (MacWindowSession) -> Content) -> some View {
        Group {
            switch startup {
            case .success(let session):
                content(session)
                    .environment(\.macSSHAgent, session.sshAgent)
                    .environment(\.macWebsiteIcons, session.websiteIcons)
                    .onChange(of: showsWebsiteIcons, initial: true) { _, enabled in session.setWebsiteIconPreference(enabled) }
                    .onAppear { session.startMonitoring() }
            case .failure:
                ContentUnavailableView {
                    Label("Could not open the vault", systemImage: "lock.trianglebadge.exclamationmark")
                } description: {
                    #if OPENVAULT_LOCAL_FIXTURE
                    Text("The isolated fixture could not start. It does not use your login Keychain or installed vault.")
                    #else
                    Text("Check that the local Keychain and vault files are available.")
                    #endif
                } actions: {
                    Button("Retry") { startup = Result { try MacWindowSession(environment: AppEnvironment(opening: .macOS)) } }
                }
            }
        }
        .macInterfaceLanguage()
        .modifier(MacAppAppearance())
        .environment(\.macLoginItemService, .live)
    }
}
