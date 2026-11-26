import AppKit
import AppShared
import SwiftUI
import UIShared
import VaultModels
import VaultRepository

extension ReviewBoards {
    func checkFunctionalFlows() async throws {
        let renderer = WindowRenderer(directory: FileManager.default.temporaryDirectory, dark: false)
        try await checkVaultSnapshots(using: renderer)
        try await checkAuthentication(using: renderer)
        try await checkSettings(using: renderer)
        try await checkMacWindowSettings(using: renderer)
        try await checkWebsiteIconBadge()
        try await checkGenerator(using: renderer)
        try await checkItemChanges(using: renderer)
        try await checkNewItemForms(using: renderer)
        try await checkMenuSession(using: renderer)
        try await checkTransferGuards(using: renderer)
    }

    private func checkAuthentication(using renderer: WindowRenderer) async throws {
        let service = FakeAuthService(loginResults: [
            .failure(RepositoryError.authenticationFailed), .success(.twoFactorRequired([.authenticator, .webAuthn])),
            .success(.twoFactorRequired([.email])), .success(.twoFactorRequired([.email])), .success(.success)
        ])
        let email = "functional@example.invalid"
        let server = "https://functional.example.invalid"
        let credential = "review-\u{4E2D}-e\u{301}!"
        let (preferences, suite) = try isolatedPreferences()
        defer { preferences.removePersistentDomain(forName: suite) }
        let model = UIShared.LoginModel(auth: service, defaults: preferences)
        var signedInServer: String?

        try await renderer.inspect(width: 560, height: 500) {
            MacLoginView(model: model) { signedInServer = $0 }
        } perform: { window in
            let submit = try await reviewAX(.button, named: "login.submit", in: window)
            try require(submit.isAccessibilityEnabled?() == false, "empty sign-in cannot submit")
            let serverField = try await requireNativeField("https://vault.example.com", in: window)
            let emailField = try await requireNativeField("邮箱地址", in: window)
            let masterField = try await requireNativeField("login.password", in: window)
            try require(serverField.convert(serverField.bounds, to: nil).midY > emailField.convert(emailField.bounds, to: nil).midY,
                        "the server field is above the email field")
            try setText(server, in: serverField)
            try setText("not-an-email", in: emailField)
            try focusEditor(for: serverField, in: window).doCommand(by: #selector(NSResponder.insertNewline(_:)))
            try await waitFor("Return moves from server to email") { focusedEditor(for: emailField, in: window) != nil }
            try focusEditor(for: emailField, in: window).doCommand(by: #selector(NSResponder.insertNewline(_:)))
            try await waitFor("Return moves from email to master password") { focusedEditor(for: masterField, in: window) != nil }
            try pasteMasterPassword(credential, into: masterField, in: window)
            try require(!model.canSubmit, "invalid email cannot submit")
            try await editText(email, field: "邮箱地址", in: window)
            try require(model.email == email && model.serverURL == server && model.password.utf8.elementsEqual(credential.utf8) && model.canSubmit,
                        "native login fields update the production model")

            try toggleMasterPasswordVisibility(nextTo: masterField, in: window)
            try await waitFor("show the unmasked master password field") {
                guard let field = nativeField("login.password", in: window), !(field is NSSecureTextField) else { return false }
                return field.stringValue.utf8.elementsEqual(credential.utf8)
            }
            let revealed = try await requireNativeField("login.password", in: window)
            try checkRomanInputSources(in: focusEditor(for: revealed, in: window))
            try toggleMasterPasswordVisibility(nextTo: revealed, in: window)
            try await waitFor("hide the master password again without altering the input") {
                nativeField("login.password", in: window) is NSSecureTextField && model.password.utf8.elementsEqual(credential.utf8)
            }
            let remasked = try await requireNativeField("login.password", in: window)
            try focusEditor(for: remasked, in: window).doCommand(by: #selector(NSResponder.insertNewline(_:)))
            try await waitFor("failed credential submission returns an error") { model.errorMessage == "验证失败，请检查输入后重试。" }
            try require(signedInServer == nil && model.password.isEmpty, "failed sign-in clears the password and cannot report success")
            try pasteMasterPassword(credential, into: try await requireNativeField("login.password", in: window), in: window)
            try await press("login.submit", in: window)
            try await waitFor("the fixture requests authenticator verification") { model.codeProviders == [.authenticator] }
            try await editText("123456", field: nil, in: window)
            try await waitFor("authenticator code entry works when a hardware key is also offered") {
                reviewNode(.button, named: "twofactor.submit", in: window)?.isAccessibilityEnabled?() == true
            }
            try await press("返回", in: window)
            _ = try await reviewAX(.textField, named: "邮箱地址", in: window)
            try require(await service.cancelledChallenges == [email] && model.password.isEmpty, "return cancels the challenge and clears the password")

            try pasteMasterPassword(credential, into: try await requireNativeField("login.password", in: window), in: window)
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
            try require(attempts.count == 3 && attempts.allSatisfy { $0.email == email && $0.password.utf8.elementsEqual(credential.utf8) && $0.server == server },
                        "the native credential fields supply all requests")
            try require(codes.map(\.code) == ["987654", "012345"] && codes.allSatisfy { $0.provider == .email && !$0.remember },
                        "code filtering, leading zero, email provider, and default remember flag reach the service")
            try require(model.password.isEmpty && model.recentServers == [server] && (preferences.stringArray(forKey: "openvault.login.recentServers") == [server]),
                        "verified sign-in clears the password and persists only the selected server in the test suite")
        }

        let keyOnlyService = FakeAuthService(loginResults: [.success(.twoFactorRequired([.webAuthn]))])
        let keyOnlyModel = UIShared.LoginModel(auth: keyOnlyService, serverURL: server, defaults: nil)
        keyOnlyModel.email = email
        keyOnlyModel.password = credential
        try await renderer.inspect(width: 560, height: 500) {
            MacLoginView(model: keyOnlyModel) { _ in }
        } perform: { window in
            try await press("login.submit", in: window)
            try await waitFor("the fixture requests hardware-key-only verification") {
                keyOnlyModel.twoFactorProviders == [.webAuthn]
            }
            let verify = try await reviewAX(.button, named: "twofactor.submit", in: window)
            try require(verify.isAccessibilityEnabled?() == false && keyOnlyModel.canUseRecoveryCode,
                        "a hardware-key-only challenge cannot submit a code but remains eligible for account recovery")
        }

        await service.lock()
        await service.setUnlockMasterError(RepositoryError.authenticationFailed)
        let unlock = UnlockModel(auth: service)
        var unlocked = false
        try await renderer.inspect(width: 560, height: 500) {
            MacUnlockView(model: unlock) { unlocked = true }
        } perform: { window in
            try await waitFor("unlock loads the active account") { unlock.email == email }
            let submit = try await reviewAX(.button, named: "unlock.submit", in: window)
            try require(submit.isAccessibilityEnabled?() == false, "empty unlock cannot submit")
            let masterField = try await requireNativeField("unlock.password", in: window)
            try await waitFor("unlock initially focuses the master password") { focusedEditor(for: masterField, in: window) != nil }
            try pasteMasterPassword("incorrect-review-input", into: masterField, in: window)
            try await press("unlock.submit", in: window)
            try await waitFor("unlock shows a validation error") { unlock.errorMessage == "验证失败，请检查输入后重试。" }
            try require(!(await service.isUnlocked()) && !unlocked, "wrong password leaves the account locked")
            await service.setUnlockMasterError(nil)
            let retryField = try await requireNativeField("unlock.password", in: window)
            try pasteMasterPassword(credential, into: retryField, in: window)
            try focusEditor(for: retryField, in: window).doCommand(by: #selector(NSResponder.insertNewline(_:)))
            try await waitFor("unlock callback") { unlocked }
            try require(await service.unlockMasterCalls.map { Array($0.utf8) } == ["incorrect-review-input", credential].map { Array($0.utf8) }
                        && unlock.password.isEmpty,
                        "unlock forwards the input and clears it on success")
        }
        print("Authentication: server-first focus order, secure master password entry, unchanged Unicode paste, challenge handling, and unlock/retry passed.")
    }

    private func nativeField(_ name: String, in window: NSWindow) -> NSTextField? {
        func control(_ node: AnyObject) -> NSTextField? {
            node as? NSTextField ?? (node as? NSCell)?.controlView as? NSTextField
        }
        return reviewNode(.textField, named: nil, in: window) { node in
            guard let field = control(node), !field.isHiddenOrHasHiddenAncestor else { return false }
            return field.accessibilityIdentifier() == name || field.placeholderString == name
                || node.accessibilityIdentifier?() == name || node.accessibilityPlaceholderValue?() == name
        }.flatMap(control)
    }

    private func requireNativeField(_ name: String, in window: NSWindow) async throws -> NSTextField {
        try await waitFor("find native field \(name)") { nativeField(name, in: window) != nil }
        guard let field = nativeField(name, in: window) else { throw CheckFailure(message: "Missing native field \(name)") }
        return field
    }

    private func focusedEditor(for field: NSTextField, in window: NSWindow) -> NSTextView? {
        guard let editor = field.currentEditor() as? NSTextView, window.firstResponder === editor else { return nil }
        return editor
    }

    private func focusEditor(for field: NSTextField, in window: NSWindow) throws -> NSTextView {
        if let editor = focusedEditor(for: field, in: window) { return editor }
        guard window.makeFirstResponder(field), let editor = focusedEditor(for: field, in: window) else {
            throw CheckFailure(message: "Could not focus native field editor")
        }
        return editor
    }

    private func checkRomanInputSources(in editor: NSTextView) throws {
        try require(editor.inputContext?.allowedInputSourceLocales == [NSAllRomanInputSourcesLocaleIdentifier],
                    "the active master password editor restricts keyboard input sources to Roman layouts")
    }

    private func toggleMasterPasswordVisibility(nextTo field: NSTextField, in window: NSWindow) throws {
        let identifier = "\(field.accessibilityIdentifier()).visibility"
        if let node = reviewNode(.button, named: identifier, in: window, matching: { $0.isAccessibilityEnabled?() == true }) {
            try require(node.accessibilityPerformPress?() == true, "activate the visibility button")
            return
        }
        let fieldFrame = field.convert(field.bounds, to: nil)
        var pending = window.contentView.map { [$0] } ?? []
        var buttons: [NSButton] = []
        while let view = pending.popLast() {
            pending += view.subviews
            guard let button = view as? NSButton, button.isEnabled, !button.isHiddenOrHasHiddenAncestor else { continue }
            let frame = button.convert(button.bounds, to: nil)
            if frame.midX > fieldFrame.maxX, (fieldFrame.minY...fieldFrame.maxY).contains(frame.midY) { buttons.append(button) }
        }
        guard buttons.count == 1, let button = buttons.first else { throw CheckFailure(message: "Missing native visibility button next to the master password") }
        button.performClick(nil)
    }

    private func pasteMasterPassword(_ value: String, into field: NSTextField, in window: NSWindow) throws {
        try require(field is NSSecureTextField, "the masked master password uses NSSecureTextField")
        let editor = try focusEditor(for: field, in: window)
        try checkRomanInputSources(in: editor)
        let board = NSPasteboard.withUniqueName()
        defer { board.releaseGlobally() }
        try require(board.setString(value, forType: .string), "write the synthetic credential to a private pasteboard")
        editor.setSelectedRange(NSRange(location: 0, length: editor.string.utf16.count))
        try require(editor.readSelection(from: board, type: .string), "paste the credential through the native field editor")
        try require(editor.string.utf8.elementsEqual(value.utf8), "pasting preserves the credential bytes")
        editor.setSelectedRange(NSRange(location: 0, length: editor.string.utf16.count))
        board.clearContents()
        try require(!editor.writeSelection(to: board, type: .string) && board.string(forType: .string) == nil,
                    "a masked credential cannot be copied out of the native field editor")
    }

    private func checkSettings(using renderer: WindowRenderer) async throws {
        let (preferences, suite) = try isolatedPreferences()
        defer { preferences.removePersistentDomain(forName: suite) }
        preferences.set(false, forKey: SettingsPreference.showsMenuBar)
        preferences.set(120.0, forKey: AppShared.Preference.clipboardTimeout)
        let service = FakeAuthService(email: "settings@example.invalid", unlocked: true, kdfIterations: 600_000)
        let vault = FakeVaultService()
        let settings = SettingsModel(serverURL: "https://settings.example.invalid")
        let timeout = MacSessionTimeoutModel()
        let sync = SyncStatusModel(vault: vault)
        let sshAgent = MacSSHAgentController(auth: service, vault: vault, defaults: preferences)
        try await renderer.inspect(width: 720, height: 465, title: "Settings") {
            MacSettingsView(auth: service, syncModel: sync, settings: settings, timeoutSettings: timeout,
                            onSetTouchID: { _ in }, onSync: {}, onAuthChange: {})
                .defaultAppStorage(preferences)
                .environment(\.macSSHAgent, sshAgent)
                .environment(\.macTouchIDAvailabilityOverride, true)
        } perform: { window in
            let tabGroup = try await reviewAX(.tabGroup, named: nil, in: window)
            let children: [Any] = tabGroup.accessibilityChildren?() ?? []
            let tabs = children.map { $0 as AnyObject }.filter { $0.accessibilityRole?() == .radioButton }
            try require(tabs.count == 6, "the system Settings tab group exposes six tabs")
            try await selectSettingsTab("通用", in: window)
            try require(preferences.object(forKey: SettingsPreference.showsWebsiteIcons) == nil, "the website icon preference is initially unset")
            try await pressSettingsSwitch("settings.menu-bar", at: 1, in: window, initially: .off)
            try await waitFor("the menu bar switch writes only its own value") {
                preferences.bool(forKey: SettingsPreference.showsMenuBar)
            }
            try require(preferences.object(forKey: MacAppPreference.keepsRunningInBackground) == nil,
                        "showing the menu bar does not change the background lifecycle")
            try await pressSettingsSwitch("settings.quick-copy", at: 3, in: window, initially: .off)
            try await waitFor("enabling quick copy persists the provider-independent setting") {
                preferences.bool(forKey: MacClipboardPreference.showsQuickCopyActions)
            }

            try await selectSettingsTab("偏好设置", in: window)
            try await pressSettingsSwitch("settings.website-icons", at: 1, in: window, initially: .on)
            try await waitFor("the default-on website icon switch writes an explicit opt-out") {
                preferences.object(forKey: SettingsPreference.showsWebsiteIcons) as? Bool == false
            }
            try await pressSettingsSwitch("settings.minimize-after-copy", at: 0, in: window, initially: .off)
            try await waitFor("clipboard minimization can be set without changing quick copy") {
                preferences.bool(forKey: MacClipboardPreference.minimizeAfterCopy)
            }
            try require(preferences.double(forKey: AppShared.Preference.clipboardTimeout) == 120,
                        "unrelated preferences preserve the clipboard timeout")

            try await selectSettingsTab("安全", in: window)
            try await pressSettingsSwitch("settings.session-timeout-guard", at: 0, in: window, initially: .on)
            try await waitFor("changing the supplemental lock updates the timeout model") { !timeout.policy.alsoLocksOnSleepOrUserSwitch }
            timeout.setMode(.never)
            try await waitFor("Never hides the supplemental lock switch") {
                visibleSettingsSwitches(in: window).count == 1
            }
            timeout.setMode(.custom)
            try await waitFor("Custom restores the supplemental lock switch alongside Touch ID") {
                visibleSettingsSwitches(in: window).count == 2
            }

            try await selectSettingsTab("同步", in: window)
            try await selectSettingsTab("账户", in: window)
            try await selectSettingsTab("集成", in: window)
            try await pressSettingsSwitch("settings.ssh-agent", at: 0, in: window, initially: .off)
            try require(reviewNode(.staticText, named: "密码与通行密钥自动填充", in: window) == nil,
                        "Mac settings do not advertise a system AutoFill provider")
            try await waitFor("the default-off SSH integration can be enabled without a socket in the review host") {
                preferences.bool(forKey: MacSSHAgentController.enabledKey) && sshAgent.status == .waitingForUnlock
            }
            try require(sshAgent.policy == .always, "new SSH agent users must authorize each signature")
            try await selectSettingsTab("偏好设置", in: window)
            try await pressSettingsSwitch("settings.website-icons", at: 1, in: window, initially: .off)
            try await waitFor("the website-icon switch persists re-enabling") { preferences.bool(forKey: SettingsPreference.showsWebsiteIcons) }
            try await selectSettingsTab("通用", in: window)
            try require(preferences.bool(forKey: SettingsPreference.showsMenuBar)
                        && preferences.bool(forKey: MacClipboardPreference.showsQuickCopyActions),
                        "global view preferences remain enabled after re-enabling website icons")
        }
        await service.lock()
        try await renderer.inspect(width: 720, height: 465, title: "Settings") {
            MacSettingsView(auth: service, syncModel: sync, settings: settings, timeoutSettings: timeout, isVaultUnlocked: false,
                            initialPane: .security, onSync: {}, onAuthChange: {})
                .macInterfaceLanguage(.english)
                .defaultAppStorage(preferences)
        } perform: { window in
            try await waitFor("Settings initially opens in the specified English Security tab") { window.title == "Security" }
            for title in ["Security", "Account", "Sync"] {
                try await selectSettingsTab(title, in: window)
                _ = try await reviewAX(.button, named: "Open OpenVault", in: window)
                try require(visibleSettingsSwitches(in: window).isEmpty, "the locked \(title) pane shows no account switches")
            }
            try await selectSettingsTab("General", in: window)
            try await pressSettingsSwitch("settings.menu-bar", at: 1, in: window, initially: .on)
            try await waitFor("the menu bar preference is editable while locked") { !preferences.bool(forKey: SettingsPreference.showsMenuBar) }
        }
        print("Settings: all six native tabs, localized window titles, locked account controls, separate global preferences, default-on icons with opt-out, and timeout guard passed.")
    }

    private func checkGenerator(using renderer: WindowRenderer) async throws {
        // Use words without embedded separators so the UI word-count check is unambiguous.
        let model = GeneratorModel(wordList: ["granite", "meadow", "orchard", "river"])
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
            let masterField = try await requireNativeField("menu.unlock.password", in: window)
            try pasteMasterPassword("disposable-panel-input", into: masterField, in: window)
            try await press("解锁", in: window)
            _ = try await reviewAX(.staticText, named: "已解锁", in: window)
            _ = try await reviewAX(.staticText, named: "最近使用", in: window)
            _ = try await reviewAX(.scrollArea, named: nil, in: window)
            try require(await service.unlockMasterCalls == ["disposable-panel-input"], "panel unlock uses entered password and restores recents")
        }
        print("Menu panel: recents, URL search, secret exclusion, clear search, lock and password unlock passed without using the system menu or general pasteboard.")
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

    private func selectSettingsTab(_ title: String, in window: NSWindow) async throws {
        let tab = try await reviewAX(.radioButton, named: title, in: window)
        try require(tab.isAccessibilityEnabled?() == true, "the native \(title) tab is enabled")
        _ = tab.accessibilityPerformPress?()
        try await waitFor("select the \(title) tab and update the window title") {
            let activeTab = reviewNode(.radioButton, named: title, in: window)
            let selection: NSNumber? = activeTab?.accessibilityValue?()
            return selection?.boolValue == true && window.title == title
        }
    }

    private func editText(_ value: String, field: String?, in window: NSWindow) async throws {
        try setText(value, in: try await reviewAX(.textField, named: field, in: window))
    }

    private func visibleSettingsSwitches(in window: NSWindow) -> [NSSwitch] {
        window.contentView?.layoutSubtreeIfNeeded()
        var pending = window.contentView.map { [$0] } ?? []
        var controls: [NSSwitch] = []
        while let view = pending.popLast() {
            pending += view.subviews
            if let control = view as? NSSwitch, !control.isHiddenOrHasHiddenAncestor { controls.append(control) }
        }
        return controls.sorted { $0.accessibilityFrame().midY > $1.accessibilityFrame().midY }
    }

    private func pressSettingsSwitch(_ identifier: String, at index: Int, in window: NSWindow, initially state: NSControl.StateValue) async throws {
        func activeSwitch() -> NSSwitch? {
            let identified = reviewNode(.button, named: identifier, in: window, matching: { $0 is NSSwitch }) as? NSSwitch
            guard let control = identified ?? visibleSettingsSwitches(in: window).dropFirst(index).first,
                  control.isEnabled else { return nil }
            return control
        }
        try await waitFor("enable the native \(identifier) switch") { activeSwitch() != nil }
        guard let control = activeSwitch() else { throw CheckFailure(message: "Missing native \(identifier) switch") }
        try require(control.state == state, "\(identifier) has the expected starting value")
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

    func isolatedPreferences() throws -> (UserDefaults, String) {
        let suite = "openvault.review.functional.\(UUID().uuidString)"
        guard let preferences = UserDefaults(suiteName: suite) else { throw CheckFailure(message: "Could not create isolated preferences") }
        return (preferences, suite)
    }
}

@MainActor @Observable private final class FunctionalMenuPhase {
    var phase: MacVaultPhase = .main
}
