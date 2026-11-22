import SwiftUI
import Networking
import UIShared
import VaultReader
import VaultRepository

/// A separate simulator app. Never constructs AppEnvironment, a Keychain or a network client.
@main
struct InterfaceFixture: App {
    private enum ForegroundSyncStep: CaseIterable { case offline, denied, authorized }

    private let auth = FakeAuthService(loginResults: [
        .success(.twoFactorRequired([.authenticator, .email])), .success(.success)
    ], email: CommandLine.arguments.contains("--fixture-login") ? nil : "studio@example.com",
    unlocked: !CommandLine.arguments.contains("--fixture-login") && !CommandLine.arguments.contains("--fixture-unlock"))
    private let vault = FakeVaultService(stored: [
        login("GitHub", user: "design", folder: "work", favorite: true, withCode: true),
        login("Apple 账户", user: "sample", folder: "personal", favorite: true, withCode: true),
        login("Dropbox", user: "studio", folder: "work", withCode: true),
        login("Microsoft", user: "work", folder: "work", withCode: true),
        login("Figma", user: "creative", folder: "work", favorite: true, withCode: true),
        login("Google", user: "home", folder: "personal", favorite: true, withCode: true),
        .init(id: "sample-card", type: 3, name: "Travel card", folderID: "personal", card: .init(brand: "Visa", number: "4242424242424242")),
        .init(id: "sample-note", type: 2, name: "设备备忘", notes: "Local review fixture", secureNote: .init()),
        .init(id: "sample-archive", type: 2, name: "Previous notes", folderID: "work", secureNote: .init(), archivedDate: .now)
    ], folders: [.init(id: "work", name: "Studio"), .init(id: "personal", name: "Personal")],
    sendService: CommandLine.arguments.contains("--fixture-sends") ? FixtureSendService() : nil,
    syncOutcome: .init(upserted: 8, deletedLocally: 0, dropped: 0, droppedMessages: [], identitiesWritten: 0,
                       profile: .init(email: "studio@example.com", name: "Morgan Lane", serverURL: "https://vault.example.com")))
    @State private var settings = SettingsModel(serverURL: "https://vault.example.com")
    @State private var showingPicker = CommandLine.arguments.contains("--fixture-autofill")
    @State private var settingReadFailure = CommandLine.arguments.contains("--fixture-read-failure")
    @State private var settingSyncIssues = CommandLine.arguments.contains("--fixture-sync-issues")
    @State private var pendingSendChanges = CommandLine.arguments.compactMap(FixtureSendService.ExternalChange.init(rawValue:))
    @State private var pendingForegroundSyncs = CommandLine.arguments.contains("--fixture-foreground-send-access") ? ForegroundSyncStep.allCases : []
    @State private var resumeSync = false
    @State private var sendReadsAtDenial: Int?
    @State private var syncAccess: VaultSyncAccess
    @State private var dataRevision: UInt64 = 0
    @Environment(\.scenePhase) private var scenePhase

    init() {
        let auth = self.auth
        _syncAccess = State(initialValue: VaultSyncAccess(currentSession: { await auth.transferSession() }))
    }

    var body: some Scene {
        WindowGroup {
            if CommandLine.arguments.contains("--fixture-backup") {
                NavigationStack { VaultTransferView(auth: auth, vault: vault) }
            } else if settingReadFailure {
                ProgressView().task {
                    let error = RepositoryError.underlying(kind: .network, description: "Simulated read failure")
                    await vault.setCiphersError(error)
                    await vault.setSearchError(error)
                    settingReadFailure = false
                }
            } else if settingSyncIssues {
                ProgressView().task {
                    await vault.setOutboxStatus(.init(issues: [
                        .init(id: 1, kind: .updateConflict, itemName: "Fixture local edit", canKeepLocalCopy: true),
                        .init(id: 2, kind: .unconfirmedCreate, itemName: "Fixture unconfirmed item", canKeepLocalCopy: true)
                    ]))
                    settingSyncIssues = false
                }
            } else {
                workspace
            }
        }
    }

    private var workspace: some View {
        RootView(auth: auth, vault: vault, settings: settings, dataRevision: dataRevision, syncAccess: syncAccess)
            .onChange(of: scenePhase) { _, phase in
                if phase == .active, resumeSync, let step = pendingForegroundSyncs.first {
                    resumeSync = false
                    pendingForegroundSyncs.removeFirst()
                    Task { await foregroundSync(step) }
                }
                guard phase == .background else { return }
                resumeSync = !pendingForegroundSyncs.isEmpty
                if CommandLine.arguments.contains("--fixture-read-failure") {
                    Task {
                        await vault.setCiphersError(nil)
                        await vault.setSearchError(nil)
                    }
                }
                if let change = pendingSendChanges.first, let sends = vault.sendService as? FixtureSendService {
                    pendingSendChanges.removeFirst()
                    Task {
                        await sends.apply(change)
                        dataRevision += 1
                    }
                }
            }
            .sheet(isPresented: $showingPicker) {
                ExtensionCredentialListView(serviceIdentifiers: ["site-1.example.com"], loadCandidates: {
                    let passwords = (1...42).map {
                        CredentialCandidate(kind: .password, name: "工作账户", user: "demo@example.com",
                                            recordID: "record-\($0)",
                                            serviceIdentifier: "https://sample-user:fixture-pass@site-\($0).example.com/private-path?session=fixture-token#fragment")
                    }
                    return passwords + [.init(kind: .passkey, name: "Studio Passkey", user: "design@example.com",
                                              recordID: "sample-passkey", serviceIdentifier: "site-1.example.com")]
                }, onSelect: { _ in showingPicker = false }, onCancel: { showingPicker = false })
                .presentationDetents([.medium, .large])
                .presentationDragIndicator(.visible)
            }
    }

    private func foregroundSync(_ step: ForegroundSyncStep) async {
        guard let sends = vault.sendService as? FixtureSendService else { return }
        switch step {
        case .offline:
            await sends.apply(.offline)
            await vault.setSyncError(NetworkingError.serverUnreachable)
        case .denied:
            sendReadsAtDenial = await sends.listReadCount
            await vault.setSyncError(NetworkingError.http(status: 403, body: "Denied by the fixture"))
        case .authorized:
            guard let sendReadsAtDenial, await sends.listReadCount > sendReadsAtDenial else { return }
            await sends.apply(.removeHandoff)
            await vault.setSyncError(nil)
        }
        _ = await VaultLifecycleSync.run(access: syncAccess, drain: { false }, synchronize: { [vault] _ in
            let outcome = try await vault.sync()
            return .init(upserted: outcome.upserted, deletedLocally: outcome.deletedLocally, dropped: outcome.dropped,
                         droppedMessages: outcome.droppedMessages, identitiesWritten: outcome.identitiesWritten,
                         profile: outcome.profile, sendCount: await sends.metadataCount)
        }, dataChanged: { dataRevision &+= 1 })
    }

    private static func login(_ title: String, user: String, folder: String, favorite: Bool = false,
                              withCode: Bool = false) -> PlaintextCipher {
        let codePeriod = user == "studio" && CommandLine.arguments.contains("--fixture-expiring-code") ? "&period=5" : ""
        return .init(id: "sample-\(user)", name: title, notes: "A personal workspace account.", folderID: folder, favorite: favorite,
              login: .init(username: "\(user)@example.com", password: "fixture-only",
                           totp: withCode ? "otpauth://totp/Studio?secret=JBSWY3DPEHPK3PXP&digits=\(user == "sample" ? 8 : 6)\(codePeriod)" : nil,
                           uris: [.init(uri: "https://\(user).example.com")],
                           fido2Credentials: [.init(rpId: "\(user).example.com", userName: "\(user)@example.com")]),
              revisionDate: .now.addingTimeInterval(-86_400))
    }
}
