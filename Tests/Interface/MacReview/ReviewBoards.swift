import AppKit
import Generators
import Networking
import SwiftUI
import UIShared
import VaultRepository

@MainActor
struct ReviewBoards {
    let auth = FakeAuthService(loginResults: [.success(.success), .success(.twoFactorRequired([.authenticator, .email]))],
                               kdfIterations: 600_000)
    let sends = FixtureSendService()
    let vault: FakeVaultService
    let settings = SettingsModel(serverURL: "https://vault.example.invalid")
    let sync: SyncStatusModel

    init() async throws {
        let names = ["GitHub", "Apple Account", "Dropbox", "Figma", "Microsoft", "Notion"]
        let folders: [PlaintextFolder] = [.init(id: "work", name: "Work"), .init(id: "personal", name: "Personal")]
        let now = Date.now
        var items: [PlaintextCipher] = names.enumerated().map { index, name in
            let host = "\(name.replacingOccurrences(of: " ", with: "").lowercased()).example.invalid"
            return PlaintextCipher(id: "login-\(index)", name: name, notes: index < 2 ? "Interface review account." : nil,
                                   folderID: index.isMultiple(of: 2) ? "work" : "personal", favorite: index < 3,
                                   login: .init(username: "review@example.invalid", password: "sample-only",
                                                totp: index < 4 ? "JBSWY3DPEHPK3PXP" : nil,
                                                uris: [.init(uri: "https://\(host)")],
                                                fido2Credentials: index < 2 ? [.init(rpId: host, userName: "review@example.invalid")] : []),
                                   revisionDate: now.addingTimeInterval(-86400), creationDate: now.addingTimeInterval(-604800))
        }
        items.append(.init(id: "note", type: 2, name: "Travel itinerary", notes: "A disposable fixture note.", secureNote: .init()))
        items.append(.init(id: "card", type: 3, name: "Travel card", card: .init(brand: "Visa", number: "4242424242424242")))
        items.append(.init(id: "trash", name: "Old router", folderID: "personal",
                           login: .init(username: "admin", password: "sample-only", uris: [.init(uri: "https://router.example.invalid")]),
                           deletedDate: now.addingTimeInterval(-86400)))
        vault = FakeVaultService(stored: items, folders: folders, sendService: sends,
                                 syncOutcome: .init(upserted: items.count, deletedLocally: 0, dropped: 0,
                                                    droppedMessages: [], identitiesWritten: 0,
                                                    profile: .init(email: "review@example.invalid", name: "Studio Review",
                                                                   serverURL: settings.serverURL), sendCount: await sends.metadataCount))
        sync = SyncStatusModel(vault: vault)
        _ = try await auth.login(email: "review@example.invalid", password: "sample-only", serverURL: settings.serverURL)
        try await auth.unlockWithMasterPassword("sample-only")
        for index in (0..<5).reversed() { await vault.recordUse(id: "login-\(index)") }
    }

    func render(using renderer: WindowRenderer) async throws {
        let login = LoginModel(auth: auth, serverURL: settings.serverURL, defaults: nil)
        login.email = "review@example.invalid"
        try await renderer.capture("Mac-Login", width: 560, height: 500, title: "登录 OpenVault") {
            MacLoginView(model: login) { _ in }
        }
        login.password = "sample-only"
        await login.submit()
        try await renderer.capture("Mac-Login-verify", width: 560, height: 500, title: "登录 OpenVault") {
            MacLoginView(model: login) { _ in }
        }
        try await renderer.capture("Mac-Unlock", width: 1280, height: 800, title: "OpenVault") {
            MacUnlockView(model: UnlockModel(auth: auth)) {}
        }
        let routes: [(String, MacDestination)] = [("Vault", .all), ("Codes", .authenticator), ("Trash", .trash),
                                                   ("Send", .send), ("Generator", .generator)]
        for (board, route) in routes {
            try await renderer.capture("Mac-\(board)", width: 1280, height: 800, title: "OpenVault") { workspace(route) }
        }
        try await renderer.captureSheet("Mac-Edit", width: 1280, height: 800,
                                        parent: { workspace(.all) }) { MacItemEditView(vault: vault) { _ in } }
        try await renderer.capture("Mac-SendNew", width: 600, height: 600) { SendEditor(service: sends) { _ in } }
        let listing = try await vault.listing()
        let personalCount = (listing.active + listing.archived).count { $0.organizationID == nil }
        for (board, mode, height): (String, VaultTransferMode, CGFloat) in [("Mac-Import", .importItems, 340), ("Mac-Export", .exportItems, 500)] {
            try await renderer.capture(board, width: 560, height: height) {
                VaultTransferView(mode: mode, auth: auth, vault: vault, personalItemCount: personalCount) {}
            }
        }
        let (preferences, suite) = try isolatedPreferences()
        defer { preferences.removePersistentDomain(forName: suite) }
        try await renderer.capture("Mac-Settings-General", width: 720, height: 465, title: "通用", toolbarStyle: .expanded) {
            MacSettingsView(auth: auth, syncModel: sync, settings: settings, onSync: {}, onAuthChange: {})
                .defaultAppStorage(preferences)
        }
        try await renderer.capture("Mac-Settings-Preferences", width: 720, height: 465, title: "偏好设置", toolbarStyle: .expanded) {
            MacSettingsView(auth: auth, syncModel: sync, settings: settings, initialPane: .preferences, onSync: {}, onAuthChange: {})
                .defaultAppStorage(preferences)
        }
        try await renderer.capture("Mac-Settings", width: 720, height: 465, title: "安全", toolbarStyle: .expanded) {
            MacSettingsView(auth: auth, syncModel: sync, settings: settings, initialPane: .security, onSync: {}, onAuthChange: {})
        }
        try await renderer.capture("Mac-Settings-Account", width: 720, height: 465, title: "账户", toolbarStyle: .expanded) {
            MacSettingsView(auth: auth, syncModel: sync, settings: settings, initialPane: .account, onSync: {}, onAuthChange: {})
        }
        try await renderer.capture("Mac-MenuBar", width: 380, height: 560) {
            MenuBarContent(auth: auth, vault: vault, phase: .main)
        }
    }

    private func workspace(_ destination: MacDestination) -> some View {
        MacMainView(auth: auth, vault: vault, syncModel: sync, dataRevision: 0, initialDestination: destination) {}
    }

    func renderSettingsBoards(using renderer: WindowRenderer) async throws {
        let (preferences, suite) = try isolatedPreferences()
        defer { preferences.removePersistentDomain(forName: suite) }
        let timeout = MacSessionTimeoutModel()
        timeout.setMode(.custom)
        let sshAgent = MacSSHAgentController(auth: auth, vault: vault, defaults: preferences)
        sshAgent.setEnabled(true)
        let loginItem = MacLoginItemService(status: { .notRegistered }, updateRegistration: { _ in }, openSettings: {})
        let groups: [(MacSettingsPane, String)] = [(.general, "General"), (.preferences, "Preferences"), (.security, "Security"),
                                                   (.account, "Account"), (.sync, "Sync"), (.integrations, "Integrations")]
        for language in [MacLanguagePreference.simplifiedChinese, .english] {
            preferences.set(language.rawValue, forKey: MacLanguagePreference.defaultsKey)
            for (pane, title) in groups {
                let localized = pane.localizedTitle(in: language.locale())
                try await renderer.capture("Mac-Settings-\(title)-\(language.rawValue)", width: 720, height: 465,
                                           title: localized, toolbarStyle: .expanded) {
                    MacSettingsView(auth: auth, syncModel: sync, settings: settings, timeoutSettings: timeout,
                                    initialPane: pane, onSync: {}, onAuthChange: {})
                        .macInterfaceLanguage(language)
                        .defaultAppStorage(preferences)
                        .environment(\.macLoginItemService, loginItem)
                        .environment(\.macSSHAgent, sshAgent)
                }
            }
        }
        if let lease = await auth.transferSession() {
            preferences.set(true, forKey: MacClipboardPreference.showsQuickCopyActions)
            try await renderer.capture("Mac-Vault-Quick-Copy", width: 1280, height: 800, title: "OpenVault") {
                MacMainView(auth: auth, vault: vault, syncModel: sync, dataRevision: 0, workspaceLease: lease) {}
                    .defaultAppStorage(preferences)
                    .transaction { $0.disablesAnimations = true }
            }
            try await renderer.capture("Mac-Vault-Quick-Copy-Compact", width: 850, height: 620, title: "OpenVault") {
                MacMainView(auth: auth, vault: vault, syncModel: sync, dataRevision: 0, workspaceLease: lease) {}
                    .macInterfaceLanguage(.english)
                    .defaultAppStorage(preferences)
                    .transaction { $0.disablesAnimations = true }
            }
        }
        try await renderNarrowCopyList(using: renderer)
    }

    func renderNarrowCopyList(using renderer: WindowRenderer) async throws {
        let model = VaultListModel(vault: vault)
        await model.load()
        try await renderer.capture("Mac-Vault-Quick-Copy-Narrow-List", width: 245, height: 620, contentOnly: true) {
            MacItemListView(items: model.items, model: model, isSearching: false, destination: .all, selection: .constant("login-0"),
                            sort: .constant(.name), onRetry: {}, onEmptyTrash: {}, hasTrash: false, snapshotRevealed: true,
                            onQuickCopy: { _, _ in })
                .macInterfaceLanguage(.english)
        }
    }

    func renderCodeBoards(using renderer: WindowRenderer) async throws {
        for (board, route): (String, MacDestination) in [("Mac-Vault", .all), ("Mac-Codes", .authenticator)] {
            let phase = Date.now.timeIntervalSince1970.truncatingRemainder(dividingBy: 30)
            let untilReference = (2.1 - phase + 30).truncatingRemainder(dividingBy: 30)
            try await Task.sleep(for: .seconds(untilReference))
            try await renderer.capture(board, width: 1280, height: 800, title: "OpenVault") { workspace(route) }
        }
    }
}

extension ReviewBoards {
    func checkInteractions(evidence: URL? = nil) async throws {
        try await checkInitialSendBadge()
        let folderNames = ["studio": "Design Team"]
        let hidden = PlaintextCipher(id: "filtered", name: "Sample router", folderID: "studio",
                                     login: .init(username: "office", password: "fixture-only"), deletedDate: .now)
        let unfiled = PlaintextCipher(type: 3, name: "Sample card", card: .init(), archivedDate: .now)
        for collection in [MacDestination.trash, .archive] {
            try require(hidden.matchesMacSearch("design team", in: collection, folderNames: folderNames), "hidden folder search")
            try require(hidden.matchesMacSearch("登录", in: collection), "hidden type search")
            try require(unfiled.matchesMacSearch("无文件夹", in: collection), "unfiled search")
            try require(!hidden.matchesMacSearch("fixture-only", in: collection), "password must not be searchable")
        }
        for collection in [MacDestination.all, .authenticator] {
            try require(!hidden.matchesMacSearch("design team", in: collection, folderNames: folderNames), "scoped search")
        }
        let message = try await sends.createSend(.init(kind: .text, name: "Studio report", text: "private message text",
                                                     deletionDate: .now.addingTimeInterval(3600), notes: "Handoff team"))
        try require(message.matchesWorkspaceSearch(" HANDOFF ") && message.matchesWorkspaceSearch("studio"), "Send metadata search")
        try require(!message.matchesWorkspaceSearch("private message text"), "Send content must not be searchable")
        let file = try await sends.listSends().first { $0.kind == .file }
        try require(file?.matchesWorkspaceSearch("Preview.pdf") == true && message.matchesWorkspaceSearch(""), "Send file and empty search")

        let renderer = WindowRenderer(directory: evidence ?? FileManager.default.temporaryDirectory, dark: false)
        try await checkSyncOutbox(using: renderer, captureEvidence: evidence != nil)
        try await checkCodeRows(using: renderer, captureEvidence: evidence != nil)
        try await checkCodeFilter(using: renderer)
        let newName = "Review authenticator"
        var savedID: String?
        try await renderer.inspect(width: 600, height: 580) {
            MacItemEditView(vault: vault, requiresCode: true) { savedID = $0 }
        } perform: { window in
            let name = try await reviewAX(.textField, named: "必填", in: window)
            let seed = try await reviewAX(.textField, named: "Base32 或 otpauth://", in: window)
            let save = try await reviewAX(.button, named: "存储", in: window)
            try setText(newName, in: name)
            try require(save.isAccessibilityEnabled?() == false, "a code needs a seed")
            try setText("not*base32", in: seed)
            try await Task.sleep(for: .milliseconds(100))
            try require(save.isAccessibilityEnabled?() == false, "reject invalid authenticator seed")
            try setText("JBSWY3DPEHPK3PXP", in: seed)
            try await waitFor("valid authenticator enables saving") {
                reviewNode(.button, named: "存储", in: window)?.isAccessibilityEnabled?() == true
            }
            let enabledSave = try await reviewAX(.button, named: "存储", in: window)
            try require(enabledSave.accessibilityPerformPress?() == true, "save native editor")
            try await waitFor("saved authenticator ID") { savedID != nil }
        }
        let saved = try await vault.cipher(id: savedID ?? "")
        let entries = MacTOTPEntry.entries(from: [saved])
        try require(saved.name == newName && entries.count == 1 && entries.first?.id == savedID, "saved login produces a code entry")
        try await checkTrashRemoval()
        try checkSendRemainingTime()
        try await checkSendSelection(using: renderer)
        try await checkSendReadCompleteness(using: renderer)
        try await checkSharedSendAccess(using: renderer)
        try await checkReadFailures(using: renderer)
    }

    private func checkSyncOutbox(using renderer: WindowRenderer, captureEvidence: Bool) async throws {
        let service = FakeVaultService()
        let model = SyncStatusModel(vault: service)
        let issue = VaultOutboxIssue(id: 1, kind: .updateConflict, itemName: "Local review edit", canKeepLocalCopy: true)
        await service.setOutboxStatus(.init(pendingCount: 1, issues: [issue]))
        try require(await model.sync(), "the fixture accepts the pull while the queue has work remaining")
        try await renderer.inspect(width: 720, height: 340, title: "同步", toolbarStyle: .expanded) {
            MacSettingsView(auth: auth, syncModel: model, settings: settings, initialPane: .sync, onSync: {}, onAuthChange: {})
        } perform: { window in
            try require(!model.statusDescription.hasPrefix("已同步"), "pending writes do not report sync success")
            try require(model.outboxStatus.issues == [issue] && model.outboxStatus.pendingCount == 1 && !model.isSyncing,
                        "the pane model retains the blocked issue and the ready upload after a pull")
            if captureEvidence { try await renderer.captureWindow(window, board: "Mac-Sync-issues") }
            try require(await model.resolve(issue, action: .keepLocalCopy), "the pane model resolves the blocked change")
            try require(model.outboxStatus.issues.isEmpty && model.outboxStatus.pendingCount == 2 && !model.isResolving,
                        "keeping the copy replaces the conflict with one ready upload")
            if captureEvidence { try await renderer.captureWindow(window, board: "Mac-Sync-pending") }
        }
        print("Sync recovery: rendered the native pane and checked its blocked and pending models before and after recovery.")
    }

    private func checkCodeRows(using renderer: WindowRenderer, captureEvidence: Bool) async throws {
        let records: [PlaintextCipher] = [
            .init(id: "first", name: "First account", login: .init(totp: "MZXW6YTBOI======")),
            .init(id: "second", name: "Second account", login: .init(totp: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"))
        ]
        let entries = MacTOTPEntry.entries(from: records)
        guard entries.count == 2 else { throw CheckFailure(message: "Missing review code entries") }
        let model = VaultListModel(vault: FakeVaultService(stored: records))
        await model.load()
        let clock = MacCodeClock()
        clock.date = Date(timeIntervalSince1970: 59)
        let finalSecond = MacCodeRowReading(entries[1], at: clock.date)
        try require(finalSecond.grouped == "287 082" && finalSecond.remaining == 1, "group only the displayed RFC test code")
        for (second, remaining, warns) in [(54, 6, false), (55, 5, true), (59, 1, true), (60, 30, false)] {
            let reading = MacCodeRowReading(entries[1], at: Date(timeIntervalSince1970: Double(second)))
            try require(reading.remaining == remaining && reading.warns(whenSelected: false) == warns && !reading.warns(whenSelected: true),
                        "only unselected rows warn in the last five seconds")
        }
        let reviewSelection = ReviewCodeSelection()
        var activationTime = Date(timeIntervalSince1970: 60)
        var copies: [String] = []
        var acceptsCopy = false
        try await renderer.inspect(width: 380, height: 320) {
            MacAuthenticatorListView(entries: entries, clock: clock, model: model,
                                     selection: Binding(get: { reviewSelection.id }, set: { reviewSelection.id = $0 }),
                                     onNewItem: {}, onRetry: {}, now: { activationTime }, copy: { value in
                                         guard acceptsCopy else { return false }
                                         copies.append(value)
                                         return true
                                     })
        } perform: { window in
            guard let table = reviewTable(in: window.contentView) else { throw CheckFailure(message: "Missing native Codes list") }
            try await waitFor("the first account is selected without activation") { table.selectedRow == 0 }
            try require(copies.isEmpty, "initial selection must not copy a code")
            try sendArrow("\u{F701}", keyCode: 125, to: table, in: window)
            try await waitFor("native next-row navigation updates selection") { reviewSelection.id == "second" }
            try sendArrow("\u{F700}", keyCode: 126, to: table, in: window)
            try await waitFor("native previous-row navigation updates selection") { reviewSelection.id == "first" }
            try require(copies.isEmpty, "directional selection must not copy either row")

            @MainActor func receipt(_ id: String) -> Bool {
                let row = reviewNode(.button, named: "mac.code.\(id)", in: window)
                let value: String? = row?.accessibilityValue?()
                return value == "已拷贝" || row?.accessibilityValueDescription?() == "已拷贝"
            }
            let failedButton = try await reviewAX(.button, named: "mac.code.second", in: window)
            try require(failedButton.accessibilityPerformPress?() == true, "select the code row with a rejected clipboard write")
            try await waitFor("a failed copy still selects the activated code row") { table.selectedRow == 1 }
            try require(copies.isEmpty && !receipt("second"), "a failed write does not report copied")
            try sendArrow("\u{F700}", keyCode: 126, to: table, in: window)
            try await waitFor("return to the first row before selecting and copying") { table.selectedRow == 0 }

            acceptsCopy = true
            let button = try await reviewAX(.button, named: "mac.code.second", in: window)
            let label = button.accessibilityLabel?() ?? button.accessibilityTitle?() ?? ""
            try require(label.contains("Second account") && label.contains("1 秒") && !label.contains("287"), "announce the account and countdown, not the code")
            try require(button.accessibilityPerformPress?() == true, "activate the unselected code row")
            try await waitFor("row activation selects and copies the current ungrouped code") {
                reviewSelection.id == "second" && table.selectedRow == 1 && copies == ["359152"] && receipt("second")
            }
            try require(!receipt("first"), "the receipt belongs only to the activated row")
            try await Task.sleep(for: .milliseconds(900))
            activationTime = Date(timeIntervalSince1970: 90)
            let selected = try await reviewAX(.button, named: "mac.code.second", in: window)
            try require(selected.accessibilityPerformPress?() == true, "activate the already-selected code row")
            try await waitFor("repeat activation reads the new period") { copies == ["359152", "969429"] }
            try await Task.sleep(for: .milliseconds(900))
            try require(receipt("second"), "repeated activation renews the row receipt")
            try await waitFor("the row receipt expires") { !receipt("second") }
            try require(copies.count == 2 && reviewSelection.id == "second", "expiry must not change selection or copy again")

            for (second, remaining) in [(54, 6), (55, 5)] {
                clock.date = Date(timeIntervalSince1970: Double(second))
                try await waitFor("Codes row shows \(remaining) seconds without a receipt") {
                    let row = reviewNode(.button, named: "mac.code.second", in: window)
                    let label = row?.accessibilityLabel?() ?? row?.accessibilityTitle?()
                    return label?.contains("\(remaining) 秒") == true && !receipt("second")
                }
                if captureEvidence { try await renderer.captureWindow(window, board: "Mac-Codes-row-\(remaining)s") }
            }
            activationTime = clock.date
            let warningRow = try await reviewAX(.button, named: "mac.code.second", in: window)
            try require(warningRow.accessibilityPerformPress?() == true, "copy the code on the first warning frame")
            try await waitFor("the Codes receipt and five seconds belong to the same row") {
                let row = reviewNode(.button, named: "mac.code.second", in: window)
                let label = row?.accessibilityLabel?() ?? row?.accessibilityTitle?()
                return label?.contains("5 秒") == true && receipt("second") && !receipt("first") && copies.last == "287082"
            }
            if captureEvidence { try await renderer.captureWindow(window, board: "Mac-Codes-row-5s-copied") }
        }
        try await renderer.inspect(width: 380, height: 320) {
            MacAuthenticatorListView(entries: entries, clock: clock, model: model,
                                     selection: .constant("second"), onNewItem: {}, onRetry: {}, copy: { _ in acceptsCopy })
                .macInterfaceLanguage(.english)
        } perform: { window in
            let identifier = "mac.code.second"
            @MainActor func receipt() -> String? {
                let node = reviewNode(.button, named: identifier, in: window)
                let value: String? = node?.accessibilityValue?()
                return value ?? node?.accessibilityValueDescription?()
            }
            let successfulCopy = try await reviewAX(.button, named: identifier, in: window)
            try require(successfulCopy.accessibilityPerformPress?() == true, "activate the English copy button")
            try await waitFor("success exposes a localized English copy receipt") { receipt() == "Copied" }
            acceptsCopy = false
            let failedCopy = try await reviewAX(.button, named: identifier, in: window)
            try require(failedCopy.accessibilityPerformPress?() == true, "reject a replacement write with a prior receipt")
            try await waitFor("failure removes a former copy receipt") { receipt()?.isEmpty != false }
        }
        print("Code copy feedback: rejected writes and localized English/Simplified Chinese receipts passed.")
        try await checkVaultCodeRow(entries[1].configuration, clock: clock, using: renderer, captureEvidence: captureEvidence)
    }

    private func checkVaultCodeRow(_ configuration: TOTPConfiguration, clock: MacCodeClock, using renderer: WindowRenderer, captureEvidence: Bool) async throws {
        var copies: [String] = []
        clock.date = Date(timeIntervalSince1970: 54)
        try await renderer.inspect(width: 640, height: 120) {
            ReviewVaultCodeRow(configuration: configuration, clock: clock) { copies.append($0) }
        } perform: { window in
            for (second, remaining) in [(54, 6), (55, 5)] {
                clock.date = Date(timeIntervalSince1970: Double(second))
                try await waitFor("Vault inspector shows \(remaining) seconds without a receipt") {
                    let row = reviewNode(.button, named: "拷贝验证码", in: window)
                    let value: String? = row?.accessibilityValue?()
                    return value == "\(remaining) 秒后更新" && copies.isEmpty
                }
                if captureEvidence { try await renderer.captureWindow(window, board: "Mac-Vault-row-\(remaining)s") }
            }
            let row = try await reviewAX(.button, named: "拷贝验证码", in: window)
            try require(row.accessibilityPerformPress?() == true, "copy the Vault inspector's code into the in-memory sink")
            try await waitFor("the Vault inspector retains the warning alongside its receipt") {
                let row = reviewNode(.button, named: "拷贝验证码", in: window)
                let value: String? = row?.accessibilityValue?()
                return value == "已拷贝" && row?.accessibilityHelp?() == "剩余 5 秒" && copies == ["287082"]
            }
            if captureEvidence { try await renderer.captureWindow(window, board: "Mac-Vault-row-5s-copied") }
        }
    }

    func reviewTable(in view: NSView?, matching: (NSTableView) -> Bool = { _ in true }) -> NSTableView? {
        guard let view else { return nil }
        if let table = view as? NSTableView, matching(table) { return table }
        for child in view.subviews {
            if let table = reviewTable(in: child, matching: matching) { return table }
        }
        return nil
    }

    private func checkCodeFilter(using renderer: WindowRenderer) async throws {
        try await renderer.inspect(width: 1280, height: 800, title: "OpenVault") {
            workspace(.authenticator)
        } perform: { window in
            _ = try await reviewAX(.staticText, named: "4 个账户", in: window)
            guard let search = window.toolbar?.items.compactMap({ $0 as? NSSearchToolbarItem }).first else {
                throw CheckFailure(message: "Missing production Codes toolbar search")
            }
            search.beginSearchInteraction()
            for (query, label) in [("dropbox", "1 个结果"), ("no-such-review-item", "0 个结果"), ("", "4 个账户")] {
                try setText(query, in: search.searchField)
                _ = try await reviewAX(.staticText, named: label, in: window)
            }
        }
    }

    func sendArrow(_ character: String, keyCode: UInt16, to table: NSTableView, in window: NSWindow) throws {
        guard let event = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [.function, .numericPad],
                                           timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: window.windowNumber,
                                           context: nil, characters: character, charactersIgnoringModifiers: character,
                                           isARepeat: false, keyCode: keyCode) else { throw CheckFailure(message: "Cannot create a review arrow event") }
        table.keyDown(with: event)
    }

    private func checkInitialSendBadge() async throws {
        let renderer = WindowRenderer(directory: FileManager.default.temporaryDirectory, dark: false)
        let expected = await sends.metadataCount
        let initialReads = await sends.listReadCount
        try await renderer.inspect(width: 1280, height: 800) {
            workspace(.all)
        } perform: { window in
            try await waitFor("initial vault sync supplies the Send count") { sync.lastOutcome?.sendCount == expected }
            try await waitFor("Send badge shows the sync count without visiting Send") { sendBadge(in: window) == String(expected) }
            let nextReads = await sends.listReadCount
            try require(nextReads == initialReads, "an unopened Send workspace must not fetch or decrypt the Send list")
            await vault.setSyncError(RepositoryError.underlying(kind: .network, description: "Review sync failure"))
            let failed = await sync.sync()
            try require(!failed, "inject a failed sync after a known Send count")
            try await waitFor("a failed sync suppresses the stale count instead of reporting zero") { sendBadge(in: window) == nil }
            await vault.setSyncError(nil)
            let recovered = await sync.sync()
            try require(recovered, "recover the synthetic sync")
            try await waitFor("a fresh sync restores the sidebar badge") { sendBadge(in: window) == String(expected) }
        }
        let unavailable = FakeVaultService(syncOutcome: await vault.syncOutcome)
        let unavailableSync = SyncStatusModel(vault: unavailable)
        try await renderer.inspect(width: 1280, height: 800) {
            MacMainView(auth: auth, vault: unavailable, syncModel: unavailableSync, dataRevision: 0) {}
        } perform: { window in
            try await waitFor("an unavailable service can still finish the vault sync") { unavailableSync.lastSync != nil }
            _ = try await reviewAX(.staticText, named: "Send", in: window)
            try require(sendBadge(in: window) == nil, "do not advertise a count without a Send service")
        }
    }

    private func sendBadge(in window: NSWindow) -> String? {
        let row = reviewNode(.staticText, named: "Send", in: window, matching: { $0.accessibilityLabel?() == "Send" })
        let value: String? = row?.accessibilityValue?()
        return value?.isEmpty == false && value != "Send" ? value : nil
    }

    private func checkTrashRemoval() async throws {
        let ids = ["first", "second", "third"]
        let removal = TrashRemovalBatch(ids: ids)
        let records = (ids + ["later"]).map { PlaintextCipher(id: $0, name: $0, deletedDate: .now) }
        let vault = FakeVaultService(stored: records)
        let cancelled = Task { @MainActor in
            try await removal.perform { try await vault.permanentlyDeleteCipher(id: $0) }
        }
        cancelled.cancel()
        do {
            _ = try await cancelled.value
            throw CheckFailure(message: "Cancelled trash removal completed")
        } catch is CancellationError {}
        try require(await vault.deletedIDs.isEmpty, "cancellation sends no deletion requests")
        let empty = try await TrashRemovalBatch(ids: []).perform { _ in throw CheckFailure(message: "Empty snapshot sent a deletion request") }
        try require(empty == 0, "empty confirmation snapshot removes nothing")

        let count = try await removal.perform { try await vault.permanentlyDeleteCipher(id: $0) }
        let removedIDs = await vault.deletedIDs
        try require(count == ids.count && removedIDs == ids, "delete only the confirmed IDs in order")
        try require(TrashRemovalBatch.receipt(for: count).contains("本机回收站") && TrashRemovalBatch.confirmationMessage.contains("离线"),
                    "confirmation and receipt distinguish local removal from server synchronization")
        try require(try await vault.listing().trash.compactMap(\.id) == ["later"], "later arrivals are not removed")

        for failureIndex in ids.indices {
            var attempted: [String] = []
            do {
                _ = try await removal.perform { id in
                    attempted.append(id)
                    if id == ids[failureIndex] { throw CheckFailure(message: "Simulated uncertain deletion") }
                }
                throw CheckFailure(message: "Trash removal ignored an unconfirmed deletion")
            } catch let failure as TrashRemovalBatch.Failure {
                try require(failure == .init(confirmed: failureIndex, unattempted: ids.count - failureIndex - 1),
                            "distinguish confirmed, unknown and unattempted deletions")
                try require(attempted == Array(ids.prefix(failureIndex + 1)), "never continue past the first failure")
                try require(failure.message.contains("未能确认") && !failure.message.contains("永久删除"), "never claim an uncertain server deletion succeeded")
            }
        }
    }

    private func checkSendRemainingTime() throws {
        let deadline = Date(timeIntervalSinceReferenceDate: 820_000_000)
        let style = SendRemainingTime(deadline: deadline).locale(Locale(identifier: "en_US"))
        for (seconds, label) in [(604_799.0, "7 days"), (59.0, "1 min"), (-120.0, "-2 min")] {
            try require(style.format(deadline.addingTimeInterval(-seconds)) == label, "signed single-unit Send countdown: \(label)")
        }
        let before = deadline.addingTimeInterval(-61)
        let boundary = deadline.addingTimeInterval(-60)
        try require(style.format(before) == "2 min" && style.discreteInput(after: before) == boundary
                    && style.format(boundary) == "1 min", "Send countdown refreshes exactly when two minutes become one")
        try require(style.discreteInput(after: deadline.addingTimeInterval(-59)) == deadline && style.format(deadline) == "0 min",
                    "the last partial minute ends at the deletion deadline")
    }

    private func checkSendSelection(using renderer: WindowRenderer) async throws {
        guard let original = try await sends.listSends().first(where: { $0.id == "handoff" }) else {
            throw CheckFailure(message: "Missing seeded Send")
        }
        var selectedID: String? = "notes"
        var query = "Design"
        let newSend = try await sends.createSend(.init(kind: .text, name: "Design update", text: "Review text", deletionDate: .now.addingTimeInterval(3600)))
        SendWorkspaceSelection.apply(newSend, selecting: true, selectedID: &selectedID, query: &query)
        try require(selectedID == newSend.id && query == "Design", "matching creation preserves the query and selects the returned Send ID")
        query = "archive"
        SendWorkspaceSelection.apply(newSend, selecting: true, selectedID: &selectedID, query: &query)
        try require(query.isEmpty && selectedID == newSend.id, "nonmatching creation reveals its returned Send")
        selectedID = original.id
        query = "Design"
        var savedID: String?
        try await renderer.inspect(width: 600, height: 600) {
            SendEditor(service: sends, item: original) { updated in
                savedID = updated.id
                SendWorkspaceSelection.apply(updated, selecting: false, selectedID: &selectedID, query: &query)
            }
        } perform: { window in
            let name = try await reviewAX(.textField, named: "必填，只有你能看到", in: window)
            try setText("Release notes", in: name)
            let save = try await reviewAX(.button, named: "send.create", in: window)
            try require(save.isAccessibilityEnabled?() == true && save.accessibilityPerformPress?() == true, "save the edited Send")
            try await waitFor("the editor returns the saved Send") { savedID == original.id }
        }
        let updated = try await sends.listSends().first { $0.id == original.id }
        try require(updated?.name == "Release notes" && selectedID == original.id && query.isEmpty, "renaming the selected Send keeps its detail visible")
        guard let updated else { throw CheckFailure(message: "Missing renamed Send") }
        query = "release"
        SendWorkspaceSelection.apply(updated, selecting: false, selectedID: &selectedID, query: &query)
        try require(selectedID == original.id && query == "release", "a matching edit retains the toolbar query")
        let cancelled = ReviewPresentation()
        var cancelledSave = false
        try await renderer.inspect(width: 600, height: 600) {
            ReviewSendPresentation(presentation: cancelled, service: sends, item: updated) { _ in cancelledSave = true }
        } perform: { window in
            let name = try await reviewAX(.textField, named: "必填，只有你能看到", in: window)
            try setText("Discarded draft", in: name)
            let cancel = try await reviewAX(.button, named: "send.cancel", in: window)
            try require(cancel.accessibilityPerformPress?() == true, "cancel Send editing")
        }
        let afterCancel = try await sends.listSends().first { $0.id == original.id }
        try require(!cancelledSave && selectedID == original.id && query == "release" && afterCancel == updated,
                    "cancelling preserves the filter and old record without dispatching a save")
        selectedID = "other"
        query = "unrelated"
        SendWorkspaceSelection.apply(newSend, selecting: false, selectedID: &selectedID, query: &query)
        try require(selectedID == "other" && query == "unrelated", "late edits must not disturb another selection")

        let first = ReviewSearch(query: "first")
        let second = ReviewSearch(query: "second")
        let firstQuery = SendWorkspaceSelection.scopedQuery(first.binding, isActive: { first.active })
        let secondQuery = SendWorkspaceSelection.scopedQuery(second.binding, isActive: { second.active })
        first.active = false
        firstQuery.wrappedValue = ""
        try require(firstQuery.wrappedValue.isEmpty && first.query == "first" && secondQuery.wrappedValue == "second", "inactive Send cannot overwrite a different destination or window")
        secondQuery.wrappedValue = "updated"
        try require(first.query == "first" && second.query == "updated", "active toolbar changes remain window-local")

        let pending = DelayedSendUpdate(service: sends)
        let presentation = ReviewPresentation()
        var staleCallback = false
        try await renderer.inspect(width: 600, height: 600) {
            ReviewSendPresentation(presentation: presentation, service: pending, item: original) { _ in staleCallback = true }
        } perform: { window in
            let save = try await reviewAX(.button, named: "send.create", in: window)
            try require(save.accessibilityPerformPress?() == true, "begin a Send update")
            try await waitForPending(pending)
            presentation.visible = false
            try await waitFor("the editor leaves its window") { reviewNode(.button, named: "send.create", in: window) == nil }
            await pending.finish()
            try await waitForSendCompletion(pending)
            try require(!staleCallback, "an editor removed during a save must not update selection after completion")
        }
    }

    private func waitForPending(_ service: DelayedSendUpdate) async throws {
        let end = ContinuousClock.now.advanced(by: .seconds(3))
        while !(await service.waiting) {
            guard ContinuousClock.now < end else { throw CheckFailure(message: "Send update did not reach the service") }
            try await Task.sleep(for: .milliseconds(40))
        }
    }

    private func waitForSendCompletion(_ service: DelayedSendUpdate) async throws {
        let end = ContinuousClock.now.advanced(by: .seconds(3))
        while !(await service.completed) {
            guard ContinuousClock.now < end else { throw CheckFailure(message: "Send update did not complete") }
            try await Task.sleep(for: .milliseconds(40))
        }
        try await Task.sleep(for: .milliseconds(80))
    }

    private func checkSendReadCompleteness(using renderer: WindowRenderer) async throws {
        let service = FixtureSendService()
        let offline = RepositoryError.underlying(kind: .network, description: "Simulated incomplete snapshot")
        await service.setReadError(offline)
        let records = SendWorkspaceRecords()
        let scope = ReviewSendScope()
        var counts: [Int?] = []
        let draft = VaultSendDraft(kind: .text, name: "Confirmed offline review", text: "Disposable body",
                                   deletionDate: .now.addingTimeInterval(3600))
        try await renderer.inspect(width: 1000, height: 700) {
            ReviewSendWorkspace(scope: scope, service: service, records: records) { counts.append($0) }
        } perform: { window in
            _ = try await sendRetry("initial Send failure", in: window)
            try require(!counts.isEmpty && counts.allSatisfy { $0 == nil }, "a failed first read never publishes zero")
            let saved = try await service.createSend(draft)
            records.store(saved)
            _ = try await reviewAX(.staticText, named: saved.name, in: window)
            guard let table = reviewTable(in: window.contentView) else { throw CheckFailure(message: "Confirmed partial Send has no native list") }
            try require(table.numberOfRows == 1 && table.selectedRow == 0 && records.state == .failed, "a confirmed Send is accessible without making the list complete")
            _ = try await sendRetry("confirmed partial Send", in: window)
            scope.query = "previously unread item"
            _ = try await reviewAX(.staticText, named: "无法读取 Send", in: window)
            try require(counts.allSatisfy { $0 == nil }, "filtering a partial snapshot does not claim empty results")
            scope.query = ""
            _ = try await reviewAX(.staticText, named: saved.name, in: window)
            try require(await service.listReadCount == 1, "creating and filtering do not fetch or decrypt the list again")

            await service.setReadError(nil)
            let retry = try await sendRetry("restored Send query", in: window)
            try require(retry.accessibilityPerformPress?() == true, "retry the missing full Send snapshot")
            try await waitFor("retry restores existing Sends and the first exact count") {
                records.items.count == 4 && records.items.contains { $0.id == "preview" } && counts.compactMap { $0 }.last == 4
                    && reviewNode(.button, named: "send.retry", in: window) == nil
            }
            let another = try await service.createSend(draft)
            records.store(another)
            try await waitFor("one confirmed creation increases the exact total once") { counts.last == 5 }
            var edited = draft
            edited.name = "Edited review record"
            let changed = try await service.updateSend(id: another.id, draft: edited)
            records.store(changed)
            try require(records.state == .complete(5) && records.items.first?.name == edited.name, "editing the existing ID does not inflate the count")
            try await service.deleteSend(id: another.id)
            records.remove(another.id)
            try await waitFor("one confirmed deletion decreases the exact total once") { counts.last == 4 }
            try require(await service.listReadCount == 2, "known mutations need no extra list read")

            await service.setReadError(offline)
            scope.revision += 1
            _ = try await sendRetry("failed Send refresh", in: window)
            try require(records.items.count == 4 && counts.last == .some(nil), "a refresh failure retains rows but suppresses stale totals")
            try require(!counts.compactMap { $0 }.contains { $0 < 4 }, "a partial count was never published")
            await service.setReadError(nil)
            let refresh = try await sendRetry("retained Send after failed refresh", in: window)
            try require(refresh.accessibilityPerformPress?() == true, "persistent refresh errors can be retried")
            try await waitFor("refresh retry restores the full count again") { counts.last == 4 }
            await service.setReadError(.locked)
            scope.revision += 1
            _ = try await sendRetry("locked Send workspace", in: window)
            try require(records.items.isEmpty && counts.last == .some(nil), "a locked session clears decrypted rows and counts")
            try require(reviewNode(.staticText, named: saved.name, in: window) == nil, "the previous session's confirmed Send is no longer visible")
        }
        await service.setReadError(nil)
        try await checkDelayedSendReads(service: service, draft: draft)
    }

    private func sendRetry(_ context: String, in window: NSWindow) async throws -> AnyObject {
        do { return try await reviewAX(.button, named: "send.retry", in: window) }
        catch { throw CheckFailure(message: "Missing retry for \(context)") }
    }

    private func checkDelayedSendReads(service: FixtureSendService, draft: VaultSendDraft) async throws {
        let delayed = ReviewDelayedSendRead(service: service)
        let records = SendWorkspaceRecords()
        let firstRead = Task { await records.read(from: delayed) }
        try await delayed.waitForRead()
        let added = try await service.createSend(draft)
        records.store(added)
        try await service.deleteSend(id: "notes")
        records.remove("notes")
        try require(records.state.count == nil, "confirmed mutations do not make a pending first read complete")
        await delayed.finish()
        await firstRead.value
        try require(records.state == .complete(4) && records.items.contains { $0.id == added.id } && !records.items.contains { $0.id == "notes" },
                    "a stale snapshot must include a later confirmed addition and exclude a later confirmed deletion")

        let superseded = Task { await records.read(from: delayed) }
        try await delayed.waitForRead()
        await records.read(from: nil)
        await delayed.finish()
        await superseded.value
        try require(records.state == .unavailable && records.items.isEmpty, "a late read cannot restore records after service removal")
        let cancelled = Task { await records.read(from: delayed) }
        try await delayed.waitForRead()
        cancelled.cancel()
        await delayed.finish()
        await cancelled.value
        try require(records.state.count == nil && records.items.isEmpty, "a cancelled read cannot publish its snapshot")
    }

    private func checkSharedSendAccess(using renderer: WindowRenderer) async throws {
        let service = FixtureSendService()
        let gated = ReviewDelayedSendRead(service: service, holdReads: false)
        let scopedVault = FakeVaultService(sendService: gated, syncOutcome: await vault.syncOutcome)
        let access = VaultSyncAccess { [auth] in await auth.transferSession() }
        let firstSync = SyncStatusModel(vault: scopedVault, syncAccess: access)
        let secondSync = SyncStatusModel(vault: scopedVault, syncAccess: access)
        let firstScope = ReviewSendScope()
        let secondScope = ReviewSendScope()

        func lifecycle() async -> Bool {
            await VaultLifecycleSync.run(access: access, drain: { false }, synchronize: { try await scopedVault.sync(for: $0) },
                                         dataChanged: { firstScope.revision += 1; secondScope.revision += 1 })
        }
        try await renderer.inspect(width: 1280, height: 800, title: "OpenVault") {
            ReviewSendWindow(auth: auth, vault: scopedVault, sync: firstSync, scope: firstScope)
        } perform: { first in
            try await renderer.inspect(width: 1280, height: 800, title: "OpenVault") {
                ReviewSendWindow(auth: auth, vault: scopedVault, sync: secondSync, scope: secondScope)
            } perform: { second in
                let windows = [first, second]
                @MainActor func hasSelection(_ window: NSWindow) -> Bool {
                    reviewNode(.button, named: "删除 Send", in: window) != nil
                        && reviewNode(.staticText, named: "https://vault.example.com/#/send/handoff", in: window) != nil
                        && reviewNode(.staticText, named: "Design handoff", in: window) != nil
                }
                @MainActor func withdrawn(_ window: NSWindow) -> Bool {
                    reviewNode(.button, named: "send.retry", in: window) != nil
                        && reviewNode(.button, named: "删除 Send", in: window) == nil
                        && reviewNode(.staticText, named: "https://vault.example.com/#/send/handoff", in: window) == nil
                        && reviewNode(.staticText, named: "Design handoff", in: window) == nil
                        && sendBadge(in: window) == nil
                }
                for window in windows {
                    try await waitFor("the Send workspace displays the selected record and its link") { hasSelection(window) }
                    try await waitFor("the Send workspace sidebar has a three-item badge") { sendBadge(in: window) == "3" }
                }
                let initialReads = await service.listReadCount
                try require(initialReads == 2, "each independent Send window loads its own complete list")
                await scopedVault.setSyncError(NetworkingError.serverUnreachable)
                try require(await lifecycle() == false, "a disconnected full sync cannot succeed")
                try await waitFor("ordinary offline sync keeps both selected details without claiming an exact total") {
                    windows.allSatisfy { hasSelection($0) && sendBadge(in: $0) == nil && reviewNode(.button, named: "send.retry", in: $0) == nil }
                }
                try require(await service.listReadCount == initialReads && firstScope.revision == 0 && secondScope.revision == 0,
                            "an offline full sync without imports neither reloads nor revokes the Send views")

                await gated.setHoldReads(true)
                firstScope.revision += 1
                do {
                    try await gated.waitForRead()
                    await scopedVault.setSyncError(NetworkingError.http(status: 403, body: "Forbidden"))
                    try require(await lifecycle() == false, "an explicit foreground full-sync denial cannot succeed")
                    try await waitFor("403 removes both selections, actions and badges before the earlier read finishes") {
                        windows.allSatisfy { withdrawn($0) }
                    }
                    try require(firstScope.revision == 1 && secondScope.revision == 0 && access.sendListingDenied,
                                "both visible windows receive denial without a data-change revision")
                } catch {
                    await gated.finish()
                    throw error
                }
                await gated.setHoldReads(false)
                await gated.finish()
                try await gated.waitForDelivery()
                try await waitFor("both windows stay revoked after the delayed successful snapshot returns") {
                    windows.allSatisfy { withdrawn($0) } && access.sendCount == nil
                }
                try require(await service.listReadCount == initialReads + 1, "denial and stale delivery do not start a fresh list request")

                try await service.deleteSend(id: "handoff")
                for window in windows {
                    let retry = try await sendRetry("a revoked window", in: window)
                    try require(retry.accessibilityPerformPress?() == true, "retry the visible Send workspace")
                    _ = try await reviewAX(.staticText, named: "Prototype preview", in: window)
                }
                try await waitFor("both retries restore the new two-item count, never the withdrawn Send") {
                    windows.allSatisfy { sendBadge(in: $0) == "2" && !hasSelection($0) && reviewNode(.button, named: "删除 Send", in: $0) != nil }
                }
                try require(await service.listReadCount == initialReads + 3, "only the two explicit retries fetch replacement snapshots")
            }
        }
    }

    private func checkReadFailures(using renderer: WindowRenderer) async throws {
        let error = RepositoryError.underlying(kind: .network, description: "Simulated read failure")
        for destination in [MacDestination.all, .authenticator] {
            await vault.setCiphersError(error)
            try await renderer.inspect(width: 1280, height: 800) {
                workspace(destination)
            } perform: { window in
                let retry = try await reviewAX(.button, named: "mac.vault.retry", in: window)
                try requireNoEmptyClaim(in: window, labels: ["0 个条目", "0 个账户", "没有条目", "没有验证码"])
                let previousReads = await vault.ciphersCallCount
                await vault.setCiphersError(nil)
                try require(retry.accessibilityPerformPress?() == true, "retry the Mac workspace read")
                try await waitFor("workspace returns from failure") { reviewNode(.button, named: "mac.vault.retry", in: window) == nil }
                let nextReads = await vault.ciphersCallCount
                try require(nextReads > previousReads, "workspace retried the repository")
            }
        }
        for recentOnly in [false, true] {
            await vault.setCiphersError(recentOnly ? nil : error)
            await vault.setRecentItemsError(recentOnly ? error : nil)
            let previousReads = await vault.ciphersCallCount
            try await renderer.inspect(width: 380, height: 560) {
                MenuBarContent(auth: auth, vault: vault, phase: .main)
            } perform: { window in
                _ = try await reviewAX(.button, named: "menu.retry", in: window)
                try requireNoEmptyClaim(in: window, labels: ["没有最近使用的条目", "没有匹配的条目"])
                if recentOnly {
                    let search = try await reviewAX(.textField, named: "搜索保险库", in: window)
                    try setText("GitHub", in: search)
                    try await waitFor("recent-list failure allows a vault search") {
                        reviewNode(.staticText, named: "搜索结果", in: window) != nil && reviewNode(.button, named: "menu.retry", in: window) == nil
                    }
                    try requireNoEmptyClaim(in: window, labels: ["没有匹配的条目"])
                    try setText("", in: search)
                    _ = try await reviewAX(.button, named: "menu.retry", in: window)
                }
                await vault.setCiphersError(nil)
                await vault.setRecentItemsError(nil)
                let availableRetry = try await reviewAX(.button, named: "menu.retry", in: window)
                try require(availableRetry.accessibilityPerformPress?() == true, "retry menu data")
                try await waitFor("menu recovers the list after retry") {
                    reviewNode(.button, named: "menu.retry", in: window) == nil && reviewNode(.busyIndicator, named: "正在载入", in: window) == nil
                }
                let nextReads = await vault.ciphersCallCount
                try require(nextReads >= previousReads + 2, "menu made a second repository read")
                try requireNoEmptyClaim(in: window, labels: ["没有最近使用的条目"])
            }
        }
    }

    private func requireNoEmptyClaim(in window: NSWindow, labels: [String]) throws {
        for label in labels {
            try require(reviewNode(.staticText, named: label, in: window) == nil, "unknown data must not appear as \(label)")
        }
    }

    func reviewAX(_ role: NSAccessibility.Role, named label: String?, in window: NSWindow) async throws -> AnyObject {
        let description = label ?? role.rawValue
        try await waitFor("find \(description)") { reviewNode(role, named: label, in: window) != nil }
        guard let node = reviewNode(role, named: label, in: window) else { throw CheckFailure(message: "Missing \(description)") }
        return node
    }

    func setText(_ value: String, in node: AnyObject) throws {
        guard let field = (node as? NSCell)?.controlView as? NSTextField ?? node as? NSTextField else {
            throw CheckFailure(message: "Missing native text field")
        }
        field.stringValue = value
        NotificationCenter.default.post(name: NSControl.textDidChangeNotification, object: field)
    }

    func reviewNode(_ role: NSAccessibility.Role, named label: String?, in window: NSWindow,
                    matching: (AnyObject) -> Bool = { _ in true }) -> AnyObject? {
        window.contentView?.layoutSubtreeIfNeeded()
        window.displayIfNeeded()
        var pending: [AnyObject] = [window]
        if let root = window.contentView { pending.append(root) }
        var visited = Set<ObjectIdentifier>()
        while let node = pending.popLast() {
            guard visited.insert(ObjectIdentifier(node)).inserted else { continue }
            if node.accessibilityRole?() == role, matching(node) {
                let value: String? = role == .staticText ? node.accessibilityValue?() : nil
                if label == nil || node.accessibilityIdentifier?() == label || node.accessibilityLabel?() == label || node.accessibilityTitle?() == label
                    || node.accessibilityPlaceholderValue?() == label || value == label { return node }
            }
            if let view = node as? NSView { pending += view.subviews }
            if let children = node.accessibilityChildren?() { pending += children.map { $0 as AnyObject } }
        }
        return nil
    }

    func waitFor(_ description: String, until condition: () -> Bool) async throws {
        let end = ContinuousClock.now.advanced(by: .seconds(3))
        while !condition() {
            guard ContinuousClock.now < end else { throw CheckFailure(message: description) }
            try await Task.sleep(for: .milliseconds(80))
        }
    }

    func require(_ condition: Bool, _ description: String) throws {
        guard condition else { throw CheckFailure(message: description) }
    }
}

@MainActor @Observable private final class ReviewCodeSelection {
    var id: String? = "first"
}

private struct ReviewVaultCodeRow: View {
    let configuration: TOTPConfiguration
    let clock: MacCodeClock
    let copy: (String) -> Void
    @State private var copied = false

    var body: some View {
        MacDetailCard {
            MacCodeCopyRow(configuration: configuration, date: clock.date, copied: copied) {
                copy(TOTP.code(for: configuration, at: clock.date))
                copied = true
            }
        }.padding(20)
    }
}

@MainActor @Observable private final class ReviewSendScope {
    var query = ""
    var revision: UInt64 = 0
}

private struct ReviewSendWindow: View {
    let auth: FakeAuthService
    let vault: FakeVaultService
    let sync: SyncStatusModel
    let scope: ReviewSendScope

    var body: some View {
        MacMainView(auth: auth, vault: vault, syncModel: sync, dataRevision: scope.revision, initialDestination: .send) {}
    }
}

private struct ReviewSendWorkspace: View {
    @Bindable var scope: ReviewSendScope
    let service: FixtureSendService
    let records: SendWorkspaceRecords
    let onCount: (Int?) -> Void

    var body: some View {
        SendWorkspace(service: service, showComposer: .constant(false), query: $scope.query,
                      onCountChange: onCount, dataRevision: scope.revision, records: records)
    }
}

struct CheckFailure: Error, CustomStringConvertible {
    let message: String
    var description: String { "Regression check failed: \(message)" }
}

@MainActor @Observable private final class ReviewPresentation {
    var visible = true
}

private struct ReviewSendPresentation: View {
    let presentation: ReviewPresentation
    let service: any VaultSendService
    let item: VaultSend
    let onSaved: (VaultSend) -> Void

    var body: some View {
        if presentation.visible {
            SendEditor(service: service, item: item, onSaved: onSaved)
        } else {
            Text("Signed out").accessibilityIdentifier("review.signedOut")
        }
    }
}

@MainActor private final class ReviewSearch {
    var active = true
    var query: String
    init(query: String) { self.query = query }
    var binding: Binding<String> { Binding(get: { self.query }, set: { self.query = $0 }) }
}

private actor DelayedSendUpdate: VaultSendService {
    let service: FixtureSendService
    private var continuation: CheckedContinuation<Void, Never>?
    private(set) var completed = false
    var waiting: Bool { continuation != nil }

    init(service: FixtureSendService) { self.service = service }
    func listSends() async throws -> [VaultSend] { try await service.listSends() }
    func createSend(_ draft: VaultSendDraft) async throws -> VaultSend { try await service.createSend(draft) }
    func deleteSend(id: String) async throws { try await service.deleteSend(id: id) }
    func updateSend(id: String, draft: VaultSendDraft) async throws -> VaultSend {
        await withCheckedContinuation { continuation = $0 }
        defer { completed = true }
        return try await service.updateSend(id: id, draft: draft)
    }
    func finish() { continuation?.resume(); continuation = nil }
}

private actor ReviewDelayedSendRead: VaultSendService {
    let service: FixtureSendService
    private var continuation: CheckedContinuation<Void, Never>?
    private var holdReads: Bool
    private var delivered = false

    init(service: FixtureSendService, holdReads: Bool = true) {
        self.service = service
        self.holdReads = holdReads
    }
    func listSends() async throws -> [VaultSend] {
        let snapshot = try await service.listSends()
        if holdReads {
            await withCheckedContinuation { continuation = $0 }
            delivered = true
        }
        return snapshot
    }
    func setHoldReads(_ value: Bool) { holdReads = value; delivered = false }
    func waitForDelivery() async throws {
        let end = ContinuousClock.now.advanced(by: .seconds(3))
        while !delivered {
            guard ContinuousClock.now < end else { throw CheckFailure(message: "The delayed Send snapshot was never delivered") }
            try await Task.sleep(for: .milliseconds(40))
        }
    }
    func waitForRead() async throws {
        let end = ContinuousClock.now.advanced(by: .seconds(3))
        while continuation == nil {
            guard ContinuousClock.now < end else { throw CheckFailure(message: "The delayed Send read did not start") }
            try await Task.sleep(for: .milliseconds(40))
        }
    }
    func finish() { continuation?.resume(); continuation = nil }
    func createSend(_ draft: VaultSendDraft) async throws -> VaultSend { try await service.createSend(draft) }
    func updateSend(id: String, draft: VaultSendDraft) async throws -> VaultSend { try await service.updateSend(id: id, draft: draft) }
    func deleteSend(id: String) async throws { try await service.deleteSend(id: id) }
}

extension FakeVaultService: GeneratorHistoryService {
    func generatorHistory() async throws -> GeneratorHistorySnapshot {
        let entries: [(GeneratorHistoryEntry.Kind, String)] = [(.username, "design+review@example.invalid"),
                                                                 (.passphrase, "fixture-wildflower-blueprint"),
                                                                 (.password, "fixture-previous-generation")]
        return GeneratorHistorySnapshot(session: AccountSessionLease(accountID: "test", generation: 0),
                                        entries: entries.enumerated().map { index, entry in
            GeneratorHistoryEntry(kind: entry.0, value: entry.1, date: .now.addingTimeInterval(-Double(index + 1) * 600))
        })
    }

    func addGeneration(_ entry: GeneratorHistoryEntry, session: AccountSessionLease) async throws {
        throw CocoaError(.featureUnsupported)
    }

    func clearGeneratorHistory(session: AccountSessionLease) async throws { throw CocoaError(.featureUnsupported) }
}
