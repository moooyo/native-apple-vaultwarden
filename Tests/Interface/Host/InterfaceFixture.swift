import SwiftUI
import UIShared
import VaultReader
import VaultRepository

/// A separate simulator app. Never constructs AppEnvironment, a Keychain or a network client.
@main
struct InterfaceFixture: App {
    private let auth = FakeAuthService(loginResults: [
        .success(.twoFactorRequired([.authenticator, .email])), .success(.success)
    ])
    private let vault = FakeVaultService(stored: [
        login("GitHub", user: "design", favorite: true, withCode: true),
        login("Apple 账户", user: "sample", favorite: true, withCode: true),
        login("Dropbox", user: "studio"),
        login("Microsoft", user: "work"),
        .init(id: "sample-note", type: 2, name: "设备备忘", notes: "本地界面示例", secureNote: .init())
    ], sendService: CommandLine.arguments.contains("--fixture-sends") ? FixtureSendService() : nil)
    @State private var settings = SettingsModel(serverURL: "https://vault.example.com")
    @State private var enteredWorkspace = false

    var body: some Scene {
        WindowGroup {
            if !enteredWorkspace, CommandLine.arguments.contains("--fixture-autofill") {
                ExtensionCredentialListView(serviceIdentifiers: ["site-1.example.com"], loadCandidates: {
                    (1...42).map {
                        CredentialCandidate(kind: .password, name: "工作账户", user: "demo@example.com",
                                            recordID: "record-\($0)",
                                            serviceIdentifier: "https://sample-user:fixture-pass@site-\($0).example.com/private-path?session=fixture-token#fragment")
                    }
                }, onSelect: { _ in enteredWorkspace = true }, onCancel: { enteredWorkspace = true })
            } else if !enteredWorkspace, CommandLine.arguments.contains("--fixture-login") {
                LoginView(model: LoginModel(auth: auth, serverURL: settings.serverURL)) { _ in
                    enteredWorkspace = true
                }
            } else if !enteredWorkspace, CommandLine.arguments.contains("--fixture-unlock") {
                UnlockView(model: UnlockModel(auth: auth), biometricsEnabled: false) {
                    enteredWorkspace = true
                }
            } else {
                MainTabView(auth: auth, vault: vault, settings: settings) {}
            }
        }
    }

    private static func login(_ title: String, user: String, favorite: Bool = false,
                              withCode: Bool = false) -> PlaintextCipher {
        .init(id: "sample-\(user)", name: title, favorite: favorite,
              login: .init(username: "\(user)@example.com", password: "fixture-only",
                           totp: withCode ? "JBSWY3DPEHPK3PXP" : nil,
                           uris: [.init(uri: "https://\(user).example.com")]))
    }
}
