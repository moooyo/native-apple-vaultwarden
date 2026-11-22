import AppKit
import AppShared
import SwiftUI
import UIShared
import VaultModels
import VaultRepository

extension ReviewBoards {
    func checkFunctionalFlows() async throws {
        let renderer = WindowRenderer(directory: FileManager.default.temporaryDirectory, dark: false)
        try await checkAuthentication(using: renderer)
        try await checkSettings(using: renderer)
        try await checkGenerator(using: renderer)
        try await checkItemChanges(using: renderer)
        try await checkNewItemForms(using: renderer)
        try await checkMenuSession(using: renderer)
        try await checkTransferGuards(using: renderer)
    }

    private func checkAuthentication(using renderer: WindowRenderer) async throws {
        let service = FakeAuthService(loginResults: [
            .failure(RepositoryError.authenticationFailed), .success(.twoFactorRequired([.authenticator])),
            .success(.twoFactorRequired([.email])), .success(.twoFactorRequired([.email])), .success(.success)
        ])
        let email = "functional@example.invalid"
        let server = "https://functional.example.invalid"
        let credential = "disposable-review-credential"
        let (preferences, suite) = try isolatedPreferences()
        defer { preferences.removePersistentDomain(forName: suite) }
        let model = UIShared.LoginModel(auth: service, defaults: preferences)
        var signedInServer: String?

        try await renderer.inspect(width: 560, height: 500) {
            MacLoginView(model: model) { signedInServer = $0 }
        } perform: { window in
            let submit = try await reviewAX(.button, named: "login.submit", in: window)
            try require(submit.isAccessibilityEnabled?() == false, "empty sign-in cannot submit")
            try await editText("not-an-email", field: "邮箱地址", in: window)
            try await editText(server, field: "https://vault.example.com", in: window)
            try await editText(credential, field: "主密码", in: window)
            try require(!model.canSubmit, "invalid email cannot submit")
            try await editText(email, field: "邮箱地址", in: window)
            try require(model.email == email && model.serverURL == server && model.password == credential && model.canSubmit,
                        "native login fields update the production model")
            try await press("login.submit", in: window)
            try await waitFor("failed credential submission returns an error") { model.errorMessage == "验证失败，请检查输入后重试。" }
            try require(signedInServer == nil, "failed sign-in cannot report success")
            try await press("login.submit", in: window)
            try await waitFor("the fixture requests authenticator verification") { model.codeProviders == [.authenticator] }
            try await press("返回", in: window)
            _ = try await reviewAX(.textField, named: "邮箱地址", in: window)
            try require(await service.cancelledChallenges == [email] && model.password.isEmpty, "return cancels the challenge and clears the password")

            try await editText(credential, field: "主密码", in: window)
            try await press("login.submit", in: window)
            try await waitFor("the fixture requests email verification") { model.codeProviders == [.email] }
            try await editText("7a2", field: nil, in: window)
            let verify = try await reviewAX(.button, named: "twofactor.submit", in: window)
            try require(verify.isAccessibilityEnabled?() == false, "a short verification code cannot submit")
            try await editText("98x76y54321", field: nil, in: window)
            try await press("twofactor.submit", in: window)
            try await waitFor("a rejected verification code does not clear the challenge") { model.isChallenged && model.errorMessage == "验证码未通过验证，请输入新的验证码。" }
            try await editText("012345", field: nil, in: window)
            try await press("twofactor.submit", in: window)
            try await waitFor("verified sign-in notifies the owning view") { signedInServer == server }
            let attempts = await service.loginCalls
            let codes = await service.twoFactorCalls
            try require(attempts.count == 3 && attempts.allSatisfy { $0.email == email && $0.password == credential && $0.server == server },
                        "the native credential fields supply all requests")
            try require(codes.map(\.code) == ["987654", "012345"] && codes.allSatisfy { $0.provider == .email && !$0.remember },
                        "code filtering, leading zero, email provider, and default remember flag reach the service")
            try require(model.password.isEmpty && model.recentServers == [server] && (preferences.stringArray(forKey: "openvault.login.recentServers") == [server]),
                        "verified sign-in clears the password and persists only the selected server in the test suite")
        }

        await service.lock()
        await service.setUnlockMasterError(RepositoryError.authenticationFailed)
        let unlock = UnlockModel(auth: service)
        var unlocked = false
        try await renderer.inspect(width: 740, height: 500) {
            MacUnlockView(model: unlock) { unlocked = true }
        } perform: { window in
            _ = try await reviewAX(.staticText, named: email, in: window)
            let submit = try await reviewAX(.button, named: "unlock.submit", in: window)
            try require(submit.isAccessibilityEnabled?() == false, "empty unlock cannot submit")
            try await editText("incorrect-review-input", field: "主密码", in: window)
            try await press("unlock.submit", in: window)
            _ = try await reviewAX(.staticText, named: "验证失败，请检查输入后重试。", in: window)
            try require(!(await service.isUnlocked()) && !unlocked, "wrong password leaves the account locked")
            await service.setUnlockMasterError(nil)
            try await editText(credential, field: "主密码", in: window)
            try await press("unlock.submit", in: window)
            try await waitFor("unlock callback") { unlocked }
            try require(await service.unlockMasterCalls == ["incorrect-review-input", credential] && unlock.password.isEmpty,
                        "unlock forwards the input and clears it on success")
        }
        print("Authentication: credential validation, rejected login and code, challenge cancel, email 2FA completion, and password unlock/retry passed.")
    }

    private func checkSettings(using renderer: WindowRenderer) async throws {
        let (preferences, suite) = try isolatedPreferences()
        defer { preferences.removePersistentDomain(forName: suite) }
        preferences.set(true, forKey: SettingsPreference.showsMenuBar)
        preferences.set(true, forKey: SettingsPreference.locksOnSleep)
        preferences.set(120.0, forKey: AppShared.Preference.clipboardTimeout)
        let service = FakeAuthService(email: "settings@example.invalid", unlocked: true, kdfIterations: 600_000)
        let vault = FakeVaultService()
        let settings = SettingsModel(serverURL: "https://settings.example.invalid", autoLockTimeout: .onSleep)
        let sync = SyncStatusModel(vault: vault)
        try await renderer.inspect(width: 720, height: 330, title: "Settings", toolbarStyle: .expanded) {
            MacSettingsView(auth: service, syncModel: sync, settings: settings, onSync: {}, onAuthChange: {})
                .defaultAppStorage(preferences)
        } perform: { window in
            try await pressSettingsSwitch(in: window)
            try await waitFor("the menu-bar switch writes fixture preferences") { !preferences.bool(forKey: SettingsPreference.showsMenuBar) }
            let clipboardPicker = try await reviewAX(.popUpButton, named: nil, in: window)
            guard let popup = (clipboardPicker as? NSCell)?.controlView as? NSPopUpButton else {
                throw CheckFailure(message: "Missing native clipboard timeout picker")
            }
            try require(popup.title == "2 分钟后", "clipboard picker presents the isolated timeout preference")

            try await press("安全", role: .checkBox, in: window)
            try await waitFor("sleep-only timeout forces the sleep switch") {
                settingsSwitch(in: window, matching: { !$0.isEnabled && $0.state == .on }) != nil
            }
            settings.autoLockTimeout = .fiveMinutes
            try await pressSettingsSwitch(in: window) { $0.state == .on }
            try await waitFor("the independent sleep switch persists") { !preferences.bool(forKey: SettingsPreference.locksOnSleep) }

            try await press("同步", role: .checkBox, in: window)
            try await waitFor("settings switches to the sync pane") { window.title == "同步" }
            try await press("账户", role: .checkBox, in: window)
            try await waitFor("settings switches to the account pane") { window.title == "账户" }
            try await press("通用", role: .checkBox, in: window)
            try await waitFor("settings switches back to the general pane") { window.title == "通用" }
            try require(settingsSwitch(in: window, matching: { $0.state == .off }) != nil, "the menu switch retains its stored value after changing panes")
        }
        print("Settings: native toolbar pane selection, isolated menu and sleep switches, and stored clipboard timeout presentation passed.")
    }

    private func checkGenerator(using renderer: WindowRenderer) async throws {
        let model = GeneratorModel()
        try await renderer.inspect(width: 1020, height: 730, title: "Generator") {
            MacGeneratorView(model: model)
        } perform: { window in
            try require(model.generated.count == model.passwordOptions.length, "generator produces an initial password")
            model.regenerate(recordInHistory: true)

            try await selectGeneratorMode("口令", in: window)
            try await waitFor("passphrase has the configured number of words") {
                model.mode == .passphrase && model.generated.components(separatedBy: "-").count == model.passphraseOptions.wordCount
            }
            model.regenerate(recordInHistory: true)

            try await selectGeneratorMode("用户名", in: window)
            try await editText("fixture", field: "基础名称", in: window)
            try await editText("invalid", field: "邮箱域名", in: window)
            try await waitFor("reject an invalid alias domain") { model.generated.isEmpty && model.errorMessage != nil }
            try await editText("example.invalid", field: "邮箱域名", in: window)
            try await waitFor("valid alias regenerates from edited options") {
                model.mode == .username && model.generated.hasPrefix("fixture+") && model.generated.hasSuffix("@example.invalid")
            }
            model.regenerate(recordInHistory: true)
            try require(model.history.map(\.kind) == [.username, .passphrase, .password], "all three generated modes are represented in history")
            try await press("隐藏生成历史", in: window)
            _ = try await reviewAX(.button, named: "显示生成历史", in: window)
            try await press("显示生成历史", in: window)
            try await press("清除", in: window)
            try await waitFor("the history clear button empties the list without erasing the current result") {
                model.history.isEmpty && !model.generated.isEmpty
            }
        }
        print("Generator: native mode selection, all three result shapes, alias validation, history inspector toggle and in-memory history clear passed.")
    }

    private func checkItemChanges(using renderer: WindowRenderer) async throws {
        var original = try await vault.cipher(id: "login-0")
        original.fields = [.init(type: FieldType.text.rawValue, name: "review label", value: "review metadata")]
        original.login?.uris[0].match = UriMatchType.host.rawValue
        original.login?.passwordRevisionDate = Date(timeIntervalSince1970: 1_700_000_000)
        guard let itemID = original.id else { throw CheckFailure(message: "Missing item ID") }
        let service = FakeVaultService(stored: [original], folders: [.init(id: "work", name: "Work")])
        let updatedName = "Edited fixture login"
        let updatedUsername = "updated@example.invalid"
        var savedID: String?
        try await renderer.inspect(width: 600, height: 670) {
            MacItemEditView(vault: service, existing: original) { savedID = $0 }
        } perform: { window in
            try await editText("  \(updatedName)  ", field: "必填", in: window)
            try await editText(updatedUsername, field: "用户名或邮箱", in: window)
            try await press("存储", in: window)
            try await waitFor("the editor submits the existing item ID") { savedID == itemID }
        }
        var expected = original
        expected.name = updatedName
        expected.login?.username = updatedUsername
        try require(try await service.cipher(id: itemID) == expected, "editing retains the passkey, folder, URI settings and custom metadata")

        let listSync = SyncStatusModel(vault: service)
        try await renderer.inspect(width: 1280, height: 800, title: "Vault") {
            MacMainView(auth: auth, vault: service, syncModel: listSync, dataRevision: 0) {}
        } perform: { window in
            try await waitFor("workspace performs the initial vault sync") { listSync.lastSync != nil }
            let initialSyncCount = await service.syncCallCount
            try await press("立即同步", in: window)
            try await waitFor("workspace sync command completes") { listSync.syncAttempt >= 2 && !listSync.isSyncing }
            try require(await service.syncCallCount == initialSyncCount + 1, "the workspace sync button reaches the service")
            try await press("归档", in: window)
            _ = try await reviewAX(.staticText, named: "已归档", in: window)
            try require(try await service.archivedCiphers().map(\.id) == [itemID], "archive moves the item out of the active list")
            try await press("撤销", in: window)
            _ = try await reviewAX(.button, named: "编辑条目", in: window)
            try require(try await service.archivedCiphers().isEmpty, "undo removes the archive mark")
            try await press("移到回收站", in: window)
            _ = try await reviewAX(.staticText, named: "已移到回收站", in: window)
            try require(try await service.trashedCiphers().map(\.id) == [itemID], "move to trash retains the item in trash")
            try await press("撤销", in: window)
            _ = try await reviewAX(.button, named: "编辑条目", in: window)
            try require(try await service.cipher(id: itemID) == expected, "undoing trash retains the edited payload and pin")
        }
        try await renderer.inspect(width: 600, height: 670) {
            MacItemEditView(vault: service, existing: expected) { savedID = $0 }
        } perform: { window in
            savedID = nil
            try await editText("", field: "必填", in: window)
            let submit = try await reviewAX(.button, named: "存储", in: window)
            try require(submit.isAccessibilityEnabled?() == false, "editing also requires a nonblank name")
            try await editText("Unsaved review changes", field: "必填", in: window)
            try await press("取消", in: window)
            let stored = try await service.cipher(id: itemID)
            try require(savedID == nil && stored == expected, "cancelling the editor does not persist draft changes")
        }
        print("Vault: native login edit and cancel preserve the passkey and metadata; workspace sync, archive, trash and undo passed.")
    }

    private func checkNewItemForms(using renderer: WindowRenderer) async throws {
        let service = FakeVaultService()
        let sshPrivateMaterial = "fixture-private-material"
        let sshPublicMaterial = "fixture-public-material"
        let forms: [(type: CipherType, name: String, field: String, value: String, matches: (PlaintextCipher) -> Bool)] = [
            (.card, "Fixture card", "持卡人姓名", "Review Person", { $0.card?.cardholderName == "Review Person" }),
            (.identity, "Fixture identity", "邮政编码", "12345", { $0.identity?.postalCode == "12345" }),
            (.sshKey, "Fixture SSH record", "密钥指纹", "disposable-fingerprint", {
                $0.sshKey == .init(privateKey: sshPrivateMaterial, publicKey: sshPublicMaterial, keyFingerprint: "disposable-fingerprint")
            }),
            (.secureNote, "Fixture note", "选填", "Disposable note content.", { $0.secureNote != nil && $0.notes == "Disposable note content." })
        ]
        for form in forms {
            let previousCreations = await service.createdCiphers.count
            var savedID: String?
            try await renderer.inspect(width: 600, height: 700) {
                MacItemEditView(vault: service, initialType: form.type) { savedID = $0 }
            } perform: { window in
                let submit = try await reviewAX(.button, named: "存储", in: window)
                try require(submit.isAccessibilityEnabled?() == false, "a new \(form.type) requires a name")
                try await editText(form.name, field: "必填", in: window)
                if form.type == .sshKey {
                    let namedSubmit = try await reviewAX(.button, named: "存储", in: window)
                    try require(namedSubmit.isAccessibilityEnabled?() == false, "an SSH name alone cannot be saved")
                    try await editText(sshPrivateMaterial, field: "私钥", in: window)
                    let privateKeySubmit = try await reviewAX(.button, named: "存储", in: window)
                    try require(privateKeySubmit.isAccessibilityEnabled?() == false, "an SSH private key alone cannot be saved")
                    let publicKey = reviewNode(.textField, named: "公钥", in: window) ?? reviewNode(.textField, named: nil, in: window) { node in
                        guard let field = (node as? NSCell)?.controlView as? NSTextField,
                              field.isEditable, !(field is NSSecureTextField) else { return false }
                        return node.accessibilityPlaceholderValue?()?.isEmpty != false && field.placeholderString?.isEmpty != false
                    }
                    guard let publicKey else { throw CheckFailure(message: "Missing native SSH public key field") }
                    try setText(sshPublicMaterial, in: publicKey)
                    try await editText(" ", field: form.field, in: window)
                    let blankFingerprintSubmit = try await reviewAX(.button, named: "存储", in: window)
                    try require(blankFingerprintSubmit.isAccessibilityEnabled?() == false, "a blank SSH fingerprint cannot be saved")
                    _ = blankFingerprintSubmit.accessibilityPerformPress?()
                    try require(await service.createdCiphers.count == previousCreations && savedID == nil, "an incomplete SSH key cannot create a record")
                }
                try await editText(form.value, field: form.field, in: window)
                try await press("存储", in: window)
                try await waitFor("save \(form.type) from its native form") { savedID != nil }
            }
            let saved = try await service.cipher(id: savedID ?? "")
            try require(saved.type == form.type.rawValue && saved.name == form.name && form.matches(saved), "the \(form.type) form persists its type-specific field")
            try require(await service.createdCiphers.count == previousCreations + 1, "the \(form.type) form creates exactly one record")
        }
        print("Vault forms: card, identity, SSH and secure note creation persist representative type-specific fields.")
    }

    private func checkMenuSession(using renderer: WindowRenderer) async throws {
        let service = FakeAuthService(email: "menu@example.invalid", unlocked: true)
        let excludedSearch = "disposable-opaque-field"
        let cipher = PlaintextCipher(id: "menu", name: "Fixture menu login",
                                     login: .init(username: "review-alias", password: excludedSearch, uris: [.init(uri: "https://listed.example.invalid")]))
        let vault = FakeVaultService(stored: [cipher])
        await vault.recordUse(id: "menu")
        let presentation = FunctionalMenuPhase()
        try await renderer.inspect(width: 380, height: 560) {
            MenuBarContent(auth: service, vault: vault, phase: presentation.phase, onRefresh: {
                if await service.isUnlocked() { presentation.phase = .main }
            }, onLock: {
                await service.lock()
                presentation.phase = .unlock
            })
        } perform: { window in
            _ = try await reviewAX(.staticText, named: "最近使用", in: window)
            _ = try await reviewAX(.scrollArea, named: nil, in: window)
            try await editText(" listed.example.invalid ", field: "搜索保险库", in: window)
            _ = try await reviewAX(.staticText, named: "搜索结果", in: window)
            _ = try await reviewAX(.scrollArea, named: nil, in: window)
            try await editText(excludedSearch, field: "搜索保险库", in: window)
            _ = try await reviewAX(.staticText, named: "没有匹配的条目", in: window)
            try await press("清除搜索", in: window)
            _ = try await reviewAX(.staticText, named: "最近使用", in: window)
            try await press("锁定保险库", in: window)
            _ = try await reviewAX(.staticText, named: "已锁定", in: window)
            let locked = !(await service.isUnlocked())
            try require(reviewNode(.textField, named: "搜索保险库", in: window) == nil && locked,
                        "the locked panel clears search and item controls")
            try await editText("disposable-panel-input", field: "主密码", in: window)
            try await press("解锁", in: window)
            _ = try await reviewAX(.staticText, named: "已解锁", in: window)
            _ = try await reviewAX(.staticText, named: "最近使用", in: window)
            _ = try await reviewAX(.scrollArea, named: nil, in: window)
            try require(await service.unlockMasterCalls == ["disposable-panel-input"], "panel unlock uses entered password and restores recents")
        }
        print("Menu panel: recents, URL search, secret exclusion, clear search, lock and password unlock passed without using the system menu or pasteboard.")
    }

    private func checkTransferGuards(using renderer: WindowRenderer) async throws {
        try await renderer.inspect(width: 560, height: 340) {
            VaultTransferView(mode: .importItems, auth: auth, vault: vault, onImported: {})
        } perform: { window in
            let submit = try await reviewAX(.button, named: "导入", in: window)
            try require(submit.isAccessibilityEnabled?() == false, "import requires a selected file")
        }
        try await renderer.inspect(width: 560, height: 500) {
            VaultTransferView(mode: .exportItems, auth: auth, vault: vault, personalItemCount: 3, onImported: {})
        } perform: { window in
            let submit = try await reviewAX(.button, named: "导出…", in: window)
            try require(submit.isAccessibilityEnabled?() == false, "export requires reauthentication")
            let prompt = "再次输入以确认"
            try await editText("incorrect-review-input", field: prompt, in: window)
            try await press("导出…", in: window)
            try await waitFor("failed reauthentication clears the export password") {
                let passwordNode = reviewNode(.textField, named: prompt, in: window)
                let password = (passwordNode as? NSCell)?.controlView as? NSTextField
                return password?.stringValue.isEmpty == true && reviewNode(.button, named: "导出…", in: window)?.isAccessibilityEnabled?() == false
            }
            try require(window.attachedSheet == nil, "invalid credentials cannot open an export panel")
        }
        print("Transfer guards: import requires a file; export rejects a wrong master password before showing a save panel.")
    }

    private func press(_ label: String, role: NSAccessibility.Role = .button, in window: NSWindow) async throws {
        func action() -> AnyObject? {
            reviewNode(role, named: label, in: window) { !($0 is NSView) && $0.isAccessibilityEnabled?() == true }
                ?? reviewNode(role, named: label, in: window) { $0.isAccessibilityEnabled?() == true }
        }
        try await waitFor("enable \(label)") { action() != nil }
        try require(action()?.accessibilityPerformPress?() == true, "activate \(label)")
    }

    private func editText(_ value: String, field: String?, in window: NSWindow) async throws {
        try setText(value, in: try await reviewAX(.textField, named: field, in: window))
    }

    private func settingsSwitch(in window: NSWindow, matching: (NSSwitch) -> Bool) -> NSSwitch? {
        for role: NSAccessibility.Role in [.button, .checkBox] {
            if let result = reviewNode(role, named: nil, in: window, matching: { node in
                (node as? NSSwitch).map(matching) == true
            }) as? NSSwitch { return result }
        }
        return nil
    }

    private func pressSettingsSwitch(in window: NSWindow, matching: (NSSwitch) -> Bool = { _ in true }) async throws {
        func activeSwitch() -> NSSwitch? { settingsSwitch(in: window) { $0.isEnabled && matching($0) } }
        try await waitFor("enable the settings switch") { activeSwitch() != nil }
        guard let control = activeSwitch() else { throw CheckFailure(message: "Missing native settings switch") }
        control.performClick(nil)
    }

    private func selectGeneratorMode(_ title: String, in window: NSWindow) async throws {
        let node = try await reviewAX(.unknown, named: "生成类型", in: window)
        guard let control = node as? NSSegmentedControl,
              let index = (0..<control.segmentCount).first(where: { control.label(forSegment: $0) == title }) else {
            throw CheckFailure(message: "Missing native generator segment \(title)")
        }
        control.selectedSegment = index
        try require(control.sendAction(control.action, to: control.target), "select generator mode \(title)")
    }

    private func isolatedPreferences() throws -> (UserDefaults, String) {
        let suite = "openvault.review.functional.\(UUID().uuidString)"
        guard let preferences = UserDefaults(suiteName: suite) else { throw CheckFailure(message: "Could not create isolated preferences") }
        return (preferences, suite)
    }
}

@MainActor @Observable private final class FunctionalMenuPhase {
    var phase: MacVaultPhase = .main
}
