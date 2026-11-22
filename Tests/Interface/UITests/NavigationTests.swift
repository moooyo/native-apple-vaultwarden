import UIKit
import Vision
import XCTest

@MainActor
final class NavigationTests: XCTestCase {
    private var originalAppearance: XCUIDevice.Appearance?

    override func setUp() {
        super.setUp()
        continueAfterFailure = false
        originalAppearance = XCUIDevice.shared.appearance
        XCUIDevice.shared.appearance = .light
    }

    override func tearDown() {
        if let originalAppearance { XCUIDevice.shared.appearance = originalAppearance }
        super.tearDown()
    }

    func testPhoneSettingsAndBottomSearchFromEachTool() throws {
        let app = try launch(on: .phone)
        let settings = app.buttons["vault.settings"]
        XCTAssertTrue(settings.waitForExistence(timeout: 7))
        XCTAssertEqual(settings.label, "设置")
        XCTAssertFalse(app.navigationBars.buttons["搜索"].exists)
        XCTAssertTrue(app.buttons["vault.pinned.sample-design"].waitForExistence(timeout: 5))
        attachScreenshot("Main")
        settings.tap()
        XCTAssertTrue(app.navigationBars["设置"].waitForExistence(timeout: 5))
        attachScreenshot("iPhone-Settings")
        app.navigationBars.buttons.element(boundBy: 0).tap()

        let search = phoneSearchTab(in: app)
        for title in ["保险库", "验证码", "Send", "生成器"] {
            let tab = app.tabBars.buttons[title]
            tab.tap()
            XCTAssertTrue(tab.wait(for: \.isSelected, toEqual: true, timeout: 5))
            XCTAssertTrue(search.wait(for: \.isHittable, toEqual: true, timeout: 5))
            XCTAssertFalse(app.searchFields.firstMatch.isHittable, "Search must not add a second field above \(title).")
            assertInLowerHalf(search, in: app)
            XCTAssertGreaterThan(search.frame.midX, tab.frame.midX)
            search.tap()
            let field = app.searchFields.firstMatch
            XCTAssertTrue(field.waitForExistence(timeout: 5))
            XCTAssertEqual(app.searchFields.count, 1)
            assertInLowerHalf(field, in: app)
            closePhoneSearch(in: app)
            XCTAssertTrue(tab.waitForExistence(timeout: 5))
            XCTAssertTrue(tab.isSelected)
        }
    }

    func testPhoneSearchOpensDetailAndCopiesPasswordInline() throws {
        let app = try launch(on: .phone)
        let search = phoneSearchTab(in: app)
        XCTAssertTrue(search.waitForExistence(timeout: 7))
        search.tap()
        let field = app.searchFields.firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        field.typeText("Dropbox")
        let result = app.buttons["vault.item.sample-studio"]
        XCTAssertTrue(result.waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["1 个结果"].waitForExistence(timeout: 5))
        attachScreenshot("iPhone-Search")
        result.tap()
        let copy = app.buttons["item.copyPassword"]
        XCTAssertTrue(copy.waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["item.revealPassword"].isHittable)
        copy.tap()
        let feedback = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value == %@", "已拷贝"), object: copy)
        XCTAssertEqual(XCTWaiter.wait(for: [feedback], timeout: 1.5), .completed)
        XCTAssertFalse(copy.label.contains("fixture-only"))
        XCTAssertFalse(app.staticTexts["fixture-only"].exists)
        let feedbackCleared = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value != %@", "已拷贝"), object: copy)
        XCTAssertEqual(XCTWaiter.wait(for: [feedbackCleared], timeout: 4), .completed)
        attachScreenshot("iPhone-Item")
    }

    func testPhoneShowsPinnedItemsAndFiltersTheList() throws {
        let app = try launch(on: .phone)
        let pinned = app.buttons["vault.pinned.sample-design"]
        XCTAssertTrue(pinned.waitForExistence(timeout: 7))
        app.buttons["vault.filter.logins"].tap()
        XCTAssertTrue(app.buttons["vault.item.sample-studio"].waitForExistence(timeout: 5))
        XCTAssertFalse(pinned.exists)
        XCTAssertFalse(app.buttons["vault.item.sample-note"].exists)
        app.buttons["vault.filter.all"].tap()
        XCTAssertTrue(pinned.waitForExistence(timeout: 5))
    }

    func testPhoneMoveToTrashUndoAndRestore() throws {
        let app = try launch(on: .phone)
        let item = app.buttons["vault.item.sample-studio"]
        scrollTo(item, in: app)
        item.swipeRight()
        app.buttons["vault.trash.sample-studio"].tap()
        let undo = app.buttons["vault.undo"]
        XCTAssertTrue(undo.waitForExistence(timeout: 3))
        undo.tap()
        XCTAssertTrue(item.waitForExistence(timeout: 5))
        item.swipeRight()
        app.buttons["vault.trash.sample-studio"].tap()

        XCTAssertTrue(item.waitForNonExistence(timeout: 5))
        XCTAssertTrue(undo.waitForNonExistence(timeout: 7))
        let trash = app.buttons["vault.trash"]
        scrollTo(trash, in: app)
        trash.tap()
        let discarded = app.descendants(matching: .any).matching(identifier: "trash.item.sample-studio").firstMatch
        XCTAssertTrue(discarded.waitForExistence(timeout: 5))
        discarded.swipeLeft()
        attachScreenshot("iPhone-Trash")
        app.buttons["trash.restore.sample-studio"].tap()
        XCTAssertTrue(discarded.waitForNonExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["回收站是空的"].exists)
        app.navigationBars.buttons.element(boundBy: 0).tap()
        scrollTo(item, in: app)
        XCTAssertTrue(item.isHittable)
    }

    func testPhoneLoginThenTwoFactor() throws {
        let app = try launch(on: .phone, arguments: ["--fixture-login"])
        let email = app.textFields["login.email"]
        let password = app.secureTextFields["login.password"]
        let login = app.buttons["login.submit"]
        XCTAssertTrue(email.waitForExistence(timeout: 5))
        XCTAssertTrue(password.exists)
        XCTAssertFalse(login.isEnabled)
        attachScreenshot("iPhone-Login")
        email.tap()
        email.typeText("studio@example.com")
        XCTAssertFalse(login.isEnabled)
        password.tap()
        password.typeText("fixture-only")
        XCTAssertTrue(login.isEnabled)
        login.tap()
        let code = app.textFields["twofactor.code"]
        let verify = app.buttons["twofactor.submit"]
        XCTAssertTrue(code.waitForExistence(timeout: 5))
        attachScreenshot("iPhone-Login-Verification")
        code.tap()
        code.typeText("12345")
        XCTAssertFalse(verify.isEnabled)
        code.typeText("6")
        XCTAssertTrue(verify.isEnabled)
        verify.tap()
        XCTAssertTrue(app.buttons["vault.settings"].waitForExistence(timeout: 5))
    }

    func testPhoneMasterPasswordUnlockWithoutBiometrics() throws {
        let app = try launch(on: .phone, arguments: ["--fixture-unlock"])
        let password = app.secureTextFields["unlock.password"]
        let unlock = app.buttons["unlock.submit"]
        XCTAssertTrue(password.waitForExistence(timeout: 5))
        XCTAssertFalse(unlock.isEnabled)
        XCTAssertTrue(app.staticTexts["studio@example.com"].waitForExistence(timeout: 5))
        attachScreenshot("iPhone-Unlock")
        password.tap()
        password.typeText("fixture-only")
        XCTAssertTrue(unlock.isEnabled)
        unlock.tap()
        XCTAssertTrue(app.buttons["vault.settings"].waitForExistence(timeout: 5))
    }

    func testPhoneAutoFillSearchAndCloseAfterScrolling() throws {
        let app = try launch(on: .phone, arguments: ["--fixture-autofill"])
        let first = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "site-1.example.com")).firstMatch
        XCTAssertTrue(first.waitForExistence(timeout: 7))
        for value in ["demo@example.com", "工作账户", "密码"] { XCTAssertTrue(first.label.contains(value)) }
        for value in ["sample-user", "fixture-pass", "private-path", "fixture-token", "fragment"] {
            XCTAssertFalse(first.label.contains(value))
            XCTAssertFalse(app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", value)).firstMatch.exists)
        }
        let other = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "site-2.example.com")).firstMatch
        XCTAssertFalse(other.exists)
        XCTAssertTrue(app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "通行密钥")).firstMatch.exists)
        attachScreenshot("iPhone-AutoFill")
        app.buttons["autofill.searchOther"].tap()
        XCTAssertTrue(other.waitForExistence(timeout: 5))
        let query = app.textFields["autofill.query"]
        query.tap()
        query.typeText("fixture-token")
        XCTAssertTrue(first.waitForNonExistence(timeout: 5))
        app.buttons["清除搜索"].tap()
        XCTAssertTrue(other.waitForExistence(timeout: 5))
        let close = app.buttons["autofill.close"]
        XCTAssertTrue(close.isHittable)
        let candidates = app.descendants(matching: .any).matching(identifier: "autofill.candidates").firstMatch
        XCTAssertTrue(candidates.waitForExistence(timeout: 5))
        for _ in 0..<5 where first.isHittable {
            let start = candidates.coordinate(withNormalizedOffset: CGVector(dx: 0.7, dy: 0.8))
            let end = candidates.coordinate(withNormalizedOffset: CGVector(dx: 0.7, dy: 0.2))
            start.press(forDuration: 0.12, thenDragTo: end)
        }
        XCTAssertFalse(first.isHittable)
        XCTAssertTrue(close.isHittable)
        close.tap()
        XCTAssertTrue(app.buttons["vault.settings"].waitForExistence(timeout: 5))
    }

    func testPhoneSendDraftValidatesAndCreatesAnItem() throws {
        let app = try launch(on: .phone, arguments: ["--fixture-sends"])
        let tab = app.tabBars.buttons["Send"]
        XCTAssertTrue(tab.waitForExistence(timeout: 7))
        tab.tap()
        XCTAssertTrue(app.buttons["拷贝“Design handoff”的链接"].waitForExistence(timeout: 5))
        attachScreenshot("iPhone-Send")
        app.buttons["send.new"].tap()
        let create = app.buttons["send.create"]
        XCTAssertTrue(create.waitForExistence(timeout: 5))
        XCTAssertFalse(create.isEnabled)
        attachScreenshot("iPhone-SendNew")
        let name = app.textFields["send.name"]
        name.tap()
        name.typeText("Interface handoff")
        XCTAssertFalse(create.isEnabled)
        let text = app.textViews["send.text"]
        text.tap()
        text.typeText("Fixture text")
        XCTAssertTrue(create.isEnabled)
        create.tap()
        XCTAssertTrue(create.waitForNonExistence(timeout: 5))
        let record = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Interface handoff")).firstMatch
        XCTAssertTrue(record.waitForExistence(timeout: 5))
        record.tap()
        XCTAssertTrue(app.buttons["拷贝共享链接"].waitForExistence(timeout: 5))
        attachScreenshot("iPhone-Send-Detail")
    }

    func testPhoneUnavailableSendServiceDoesNotCreateALink() throws {
        let app = try launch(on: .phone)
        let tab = app.tabBars.buttons["Send"]
        XCTAssertTrue(tab.waitForExistence(timeout: 7))
        tab.tap()
        app.buttons["send.new"].tap()
        let name = app.textFields["send.name"]
        let content = app.textViews["send.text"]
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        name.tap()
        name.typeText("Unavailable draft")
        content.tap()
        content.typeText("Fixture text")
        XCTAssertFalse(app.buttons["send.create"].isEnabled)
        app.buttons["send.cancel"].tap()
        XCTAssertTrue(name.waitForNonExistence(timeout: 5))
        XCTAssertFalse(app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "Unavailable draft")).firstMatch.exists)
    }

    func testPhoneOpenSendDetailTracksRemoteChangesAndAccess() throws {
        let app = try launch(on: .phone, arguments: ["--fixture-sends", "--fixture-send-offline", "--fixture-send-remove-handoff", "--fixture-send-revoke-then-recover"])
        let tab = app.tabBars.buttons["Send"]
        XCTAssertTrue(tab.waitForExistence(timeout: 7))
        tab.tap()

        let handoff = sendButton("Design handoff", in: app)
        let preview = sendButton("Prototype preview", in: app)
        let notes = sendButton("Studio notes", in: app)
        let detailLink = app.buttons["拷贝共享链接"]
        let retry = app.buttons["send.retry"]
        func checkUnreadable(line: UInt = #line) {
            XCTAssertTrue(retry.wait(for: \.isHittable, toEqual: true, timeout: 5), line: line)
            XCTAssertFalse(handoff.exists || preview.exists || notes.exists, line: line)
            XCTAssertFalse(detailLink.exists, line: line)
            checkSendFilterCounts([nil, nil, nil], in: app, line: line)
        }

        XCTAssertTrue(handoff.wait(for: \.isHittable, toEqual: true, timeout: 5))
        for metadata in ["删除时间", "已访问"] {
            XCTAssertEqual(handoff.label.components(separatedBy: metadata).count - 1, 1)
        }
        handoff.tap()
        XCTAssertTrue(detailLink.wait(for: \.isHittable, toEqual: true, timeout: 5))

        resumeFixture(app)
        XCTAssertTrue(detailLink.wait(for: \.isHittable, toEqual: true, timeout: 5))
        app.buttons["关闭"].tap()
        XCTAssertTrue(retry.wait(for: \.isHittable, toEqual: true, timeout: 5))
        handoff.tap()
        XCTAssertTrue(detailLink.wait(for: \.isHittable, toEqual: true, timeout: 5))

        resumeFixture(app)
        XCTAssertTrue(tab.wait(for: \.isHittable, toEqual: true, timeout: 5))
        XCTAssertFalse(handoff.exists)
        XCTAssertFalse(detailLink.exists)
        XCTAssertFalse(retry.exists)
        XCTAssertTrue(notes.exists)
        checkSendFilterCounts([2, 1, 1], in: app)
        preview.tap()
        XCTAssertTrue(detailLink.wait(for: \.isHittable, toEqual: true, timeout: 5))

        resumeFixture(app)
        XCTAssertTrue(tab.wait(for: \.isHittable, toEqual: true, timeout: 5))
        checkUnreadable()
        retry.tap()
        checkUnreadable()
        retry.tap()
        XCTAssertTrue(preview.wait(for: \.isHittable, toEqual: true, timeout: 5))
        XCTAssertFalse(handoff.exists || notes.exists || retry.exists)
        XCTAssertFalse(detailLink.exists)
        checkSendFilterCounts([1, 0, 1], in: app)
        preview.tap()
        XCTAssertTrue(detailLink.wait(for: \.isHittable, toEqual: true, timeout: 5))
    }

    func testPhoneForegroundSyncDenialClearsOpenSendWhileListIsOffline() throws {
        let app = try launch(on: .phone, arguments: ["--fixture-sends", "--fixture-foreground-send-access"])
        let tab = app.tabBars.buttons["Send"]
        XCTAssertTrue(tab.wait(for: \.isHittable, toEqual: true, timeout: 7))
        tab.tap()
        let handoff = sendButton("Design handoff", in: app)
        let preview = sendButton("Prototype preview", in: app)
        let notes = sendButton("Studio notes", in: app)
        let detailLink = app.buttons["拷贝共享链接"]
        let retry = app.buttons["send.retry"]
        XCTAssertTrue(handoff.wait(for: \.isHittable, toEqual: true, timeout: 5))
        checkSendFilterCounts([3, 2, 1], in: app)
        handoff.tap()
        XCTAssertTrue(detailLink.wait(for: \.isHittable, toEqual: true, timeout: 5))

        resumeFixture(app)
        XCTAssertTrue(detailLink.wait(for: \.isHittable, toEqual: true, timeout: 5))

        resumeFixture(app)
        func checkRevoked(line: UInt = #line) {
            XCTAssertTrue(retry.wait(for: \.isHittable, toEqual: true, timeout: 5), line: line)
            XCTAssertTrue(tab.isHittable, line: line)
            XCTAssertFalse(detailLink.exists || handoff.exists || preview.exists || notes.exists, line: line)
            checkSendFilterCounts([nil, nil, nil], in: app, line: line)
        }
        checkRevoked()
        retry.tap()
        checkRevoked()

        resumeFixture(app)
        XCTAssertTrue(preview.wait(for: \.isHittable, toEqual: true, timeout: 5))
        XCTAssertTrue(notes.exists)
        XCTAssertFalse(retry.exists || handoff.exists || detailLink.exists)
        checkSendFilterCounts([2, 1, 1], in: app)
        preview.tap()
        XCTAssertTrue(detailLink.wait(for: \.isHittable, toEqual: true, timeout: 5))
    }

    private func resumeFixture(_ app: XCUIApplication) {
        XCUIDevice.shared.press(.home)
        app.activate()
    }

    private func sendButton(_ name: String, in app: XCUIApplication) -> XCUIElement {
        app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", name)).firstMatch
    }

    private func checkSendFilterCounts(_ expected: [Int?], in app: XCUIApplication, line: UInt = #line) {
        let filters = ["全部", "文本", "文件"].map { sendButton($0, in: app) }
        XCTAssertTrue(filters.allSatisfy(\.exists), line: line)
        XCTAssertEqual(filters.map { Int($0.label.filter(\.isNumber)) }, expected, line: line)
    }

    func testPadVaultSplitViewAndBottomSearch() throws {
        let app = try launch(on: .pad)
        let listRow = app.buttons["pad.item.sample-studio"]
        XCTAssertTrue(listRow.waitForExistence(timeout: 7))
        let sidebarWasOpen = setPadSidebar(expanded: true, in: app)
        defer { setPadSidebar(expanded: sidebarWasOpen, in: app) }
        func showsFixtureCount(_ tab: XCUIElement) -> Bool {
            tab.label.contains("8") || (tab.value as? String)?.contains("8") == true || tab.staticTexts["8"].exists
        }
        let sidebarVault = app.cells["tab.vault"]
        XCTAssertTrue(sidebarVault.waitForExistence(timeout: 5))
        XCTAssertTrue(showsFixtureCount(sidebarVault), sidebarVault.debugDescription)
        let lastPinned = app.buttons["pad.item.sample-home"]
        let unpinnedNote = app.buttons["pad.item.sample-note"]
        XCTAssertTrue(lastPinned.exists && unpinnedNote.exists)
        XCTAssertLessThan(lastPinned.frame.midY, min(unpinnedNote.frame.midY, listRow.frame.midY))
        listRow.tap()
        let detail = app.buttons["item.copyPassword"]
        XCTAssertTrue(detail.waitForExistence(timeout: 5))
        XCTAssertTrue(listRow.isSelected)
        XCTAssertGreaterThan(detail.frame.midX, listRow.frame.midX)
        attachScreenshot("iPad-Vault-Sidebar")
        setPadSidebar(expanded: false, in: app)
        XCTAssertTrue(app.buttons["vault.filter.logins"].waitForExistence(timeout: 5))
        let topVault = padTab("保险库", identifier: "tab.vault", in: app)
        XCTAssertTrue(topVault.exists)
        XCTAssertFalse(showsFixtureCount(topVault), topVault.debugDescription)
        XCTAssertTrue(listRow.isHittable)
        XCTAssertTrue(detail.isHittable)
        attachScreenshot("iPad-Vault")
        let open = app.buttons["search.open"]
        XCTAssertTrue(open.waitForExistence(timeout: 7))
        assertInLowerHalf(open, in: app)
        open.tap()
        let query = app.textFields["search.field"]
        XCTAssertTrue(query.waitForExistence(timeout: 5))
        assertInLowerHalf(query, in: app)
        app.buttons["search.close"].tap()
        XCTAssertTrue(listRow.waitForExistence(timeout: 5))
        XCTAssertTrue(detail.isHittable)
        XCTAssertTrue(app.keyboards.firstMatch.waitForNonExistence(timeout: 5))
        XCTAssertTrue(open.wait(for: \.isHittable, toEqual: true, timeout: 5))
        open.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
        XCTAssertTrue(query.waitForExistence(timeout: 5))
        query.tap()
        query.typeText("Dropbox")
        let result = app.buttons["vault.item.sample-studio"]
        XCTAssertTrue(result.waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["1 个结果"].waitForExistence(timeout: 5))
        attachScreenshot("iPad-Search")
        result.tap()
        XCTAssertTrue(detail.waitForExistence(timeout: 5))
        XCTAssertTrue(listRow.isHittable)
        XCTAssertGreaterThan(detail.frame.midX, listRow.frame.maxX)
        XCTAssertFalse(query.exists)
    }

    func testPadCodesAndGeneratorHistory() throws {
        let app = try launch(on: .pad)
        let sidebarWasOpen = setPadSidebar(expanded: false, in: app)
        defer { setPadSidebar(expanded: sidebarWasOpen, in: app) }
        let codes = padTab("验证码", identifier: "tab.codes", in: app)
        XCTAssertTrue(codes.waitForExistence(timeout: 7))
        codes.tap()
        let code = app.buttons["codes.copy.sample-design"]
        XCTAssertTrue(code.waitForExistence(timeout: 5))
        XCTAssertTrue(code.isHittable)
        attachScreenshot("iPad-Codes")
        code.tap()

        padTab("生成器", identifier: "tab.generator", in: app).tap()
        let generate = app.buttons["重新生成"]
        XCTAssertTrue(generate.waitForExistence(timeout: 5))
        attachScreenshot("iPad-Generator")
        generate.tap()
        app.buttons["生成历史"].tap()
        let historyItem = app.buttons.matching(identifier: "拷贝密码").firstMatch
        XCTAssertTrue(historyItem.waitForExistence(timeout: 5))
        historyItem.tap()
        app.buttons["清除"].tap()
        XCTAssertTrue(app.staticTexts["没有生成历史"].waitForExistence(timeout: 5))
        app.buttons["完成"].tap()
        XCTAssertTrue(generate.waitForExistence(timeout: 5))
    }

    func testPhoneFoldersEditorAndTransfer() throws {
        let app = try launch(on: .phone)
        let studio = app.buttons["vault.folder.work"]
        scrollTo(studio, in: app)
        studio.tap()
        XCTAssertTrue(app.buttons["vault.item.sample-studio"].waitForExistence(timeout: 5))
        attachScreenshot("iPhone-Folder")
        app.buttons["在此文件夹新建条目"].tap()
        try checkEditor(in: app, board: "iPhone-NewItem")
        app.navigationBars.buttons.element(boundBy: 0).tap()
        app.buttons["vault.settings"].tap()
        let folders = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "文件夹")).firstMatch
        scrollTo(folders, in: app)
        folders.tap()
        XCTAssertTrue(studio.waitForExistence(timeout: 5))
        studio.swipeLeft()
        XCTAssertTrue(app.buttons["重命名"].waitForExistence(timeout: 5))
        attachScreenshot("iPhone-Folders")
        app.navigationBars.buttons.element(boundBy: 0).tap()
        let transfer = app.buttons["导入与导出"]
        scrollTo(transfer, in: app)
        transfer.tap()
        let chooser = app.buttons["选择文件并导入…"]
        XCTAssertTrue(chooser.waitForExistence(timeout: 5))
        XCTAssertTrue(chooser.isEnabled)
        attachScreenshot("iPhone-ImportExport")
        app.segmentedControls.buttons["导出"].tap()
        XCTAssertTrue(app.secureTextFields.firstMatch.waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["导出…"].isEnabled)
        attachScreenshot("iPhone-ImportExport-Export")
    }

    func testPhoneCodesAndGenerator() throws {
        let app = try launch(on: .phone)
        let codes = app.tabBars.buttons["验证码"]
        XCTAssertTrue(codes.waitForExistence(timeout: 5))
        codes.tap()
        XCTAssertTrue(app.buttons["codes.copy.sample-design"].waitForExistence(timeout: 5))
        attachScreenshot("iPhone-Codes")
        app.tabBars.buttons["生成器"].tap()
        XCTAssertTrue(app.buttons["重新生成"].waitForExistence(timeout: 5))
        attachScreenshot("iPhone-Generator")
    }

    func testPhoneExpiringCodeKeepsVisibleSecondsDuringCopy() throws {
        let app = try launch(on: .phone, arguments: ["--fixture-expiring-code"])
        let tab = app.tabBars.buttons["验证码"]
        XCTAssertTrue(tab.wait(for: \.isHittable, toEqual: true, timeout: 5))
        tab.tap()
        let row = app.buttons["codes.copy.sample-studio"]
        XCTAssertTrue(row.wait(for: \.isHittable, toEqual: true, timeout: 5))

        func checkVisibleStatus(_ image: XCUIScreenshot, copied: Bool, line: UInt = #line) throws {
            let pixels = try XCTUnwrap(image.image.cgImage, line: line)
            let offset = pixels.width * 3 / 5
            let status = try XCTUnwrap(pixels.cropping(to: CGRect(x: offset, y: 0, width: pixels.width - offset, height: pixels.height)), line: line)
            let request = VNRecognizeTextRequest()
            request.recognitionLevel = .accurate
            request.recognitionLanguages = ["zh-Hans"]
            request.usesLanguageCorrection = false
            try VNImageRequestHandler(cgImage: status).perform([request])
            let text = (request.results ?? []).compactMap { $0.topCandidates(1).first?.string }.joined().filter { !$0.isWhitespace }
            XCTAssertTrue((1...5).contains { text.contains("\($0)秒") }, "The row must visibly show its remaining seconds.", line: line)
            XCTAssertEqual(text.contains("已拷贝"), copied, "The visible receipt must belong to the tapped row.", line: line)
        }

        try checkVisibleStatus(row.screenshot(), copied: false)
        row.tap()
        let copiedFrame = row.screenshot()
        XCTAssertEqual(row.value as? String, "已拷贝")
        try checkVisibleStatus(copiedFrame, copied: true)
        let cleared = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value != %@", "已拷贝"), object: row)
        XCTAssertEqual(XCTWaiter.wait(for: [cleared], timeout: 3), .completed)
        try checkVisibleStatus(row.screenshot(), copied: false)
    }

    func testPadEditorSettingsAndSend() throws {
        let app = try launch(on: .pad, arguments: ["--fixture-sends"])
        let sidebarWasOpen = setPadSidebar(expanded: false, in: app)
        defer { setPadSidebar(expanded: sidebarWasOpen, in: app) }
        let create = app.buttons["新建条目"]
        XCTAssertTrue(create.waitForExistence(timeout: 7))
        create.tap()
        try checkEditor(in: app, board: "iPad-NewItem")
        app.buttons["navigation.settings"].firstMatch.tap()
        let sync = app.buttons["立即同步"]
        XCTAssertTrue(sync.waitForExistence(timeout: 5))
        XCTAssertGreaterThan(sync.frame.midX, app.frame.midX)
        attachScreenshot("iPad-Settings")
        app.buttons["settings.back"].tap()
        padTab("Send", identifier: "tab.send", in: app).tap()
        let link = app.buttons["拷贝共享链接"]
        XCTAssertTrue(link.waitForExistence(timeout: 5))
        XCTAssertGreaterThan(link.frame.midX, app.frame.width * 0.4)
        attachScreenshot("iPad-Send")
        setPadSidebar(expanded: true, in: app)
        XCTAssertTrue(link.wait(for: \.isHittable, toEqual: true, timeout: 5))
        attachScreenshot("iPad-Send-Sidebar")
    }

    func testPadSignInAndUnlockLayout() throws {
        let login = try launch(on: .pad, arguments: ["--fixture-login"])
        let submit = login.buttons["login.submit"]
        XCTAssertTrue(submit.waitForExistence(timeout: 5))
        XCTAssertEqual(submit.frame.midX, login.frame.midX, accuracy: 8)
        XCTAssertLessThan(submit.frame.width, login.frame.width / 2)
        attachScreenshot("iPad-Login")
        login.terminate()
        let unlock = try launch(on: .pad, arguments: ["--fixture-unlock"])
        let confirm = unlock.buttons["unlock.submit"]
        XCTAssertTrue(confirm.waitForExistence(timeout: 5))
        XCTAssertTrue(unlock.staticTexts["studio@example.com"].waitForExistence(timeout: 5))
        XCTAssertEqual(confirm.frame.midX, unlock.frame.midX, accuracy: 8)
        XCTAssertLessThan(confirm.frame.width, unlock.frame.width / 2)
        attachScreenshot("iPad-Unlock")
    }

    func testPhoneLargestCodesInDarkAppearance() throws {
        try XCTSkipUnless(UIDevice.current.userInterfaceIdiom == .phone, "Run on iPhone.")
        let device = XCUIDevice.shared
        let appearance = device.appearance
        defer { device.appearance = appearance }
        device.appearance = .dark
        let accessibilityArguments = ["-openvault.appearance.theme", "dark", "-UIPreferredContentSizeCategoryName",
                                      UIContentSizeCategory.accessibilityExtraExtraExtraLarge.rawValue]
        let app = try launch(on: .phone, arguments: accessibilityArguments)
        let tab = app.tabBars.buttons["验证码"]
        XCTAssertTrue(tab.waitForExistence(timeout: 5))
        tab.tap()
        let code = app.buttons["codes.copy.sample-sample"]
        XCTAssertTrue(code.waitForExistence(timeout: 5))
        XCTAssertGreaterThan(code.frame.height, 100)
        XCTAssertGreaterThanOrEqual(code.frame.minX, app.frame.minX)
        XCTAssertLessThanOrEqual(code.frame.maxX, app.frame.maxX)
        let image = XCUIScreen.main.screenshot()
        let pixels = try XCTUnwrap(image.image.cgImage)
        let sample = CGRect(x: pixels.width / 5, y: pixels.height / 55, width: 3, height: 3)
        let background = try XCTUnwrap(pixels.cropping(to: sample))
        let context = try XCTUnwrap(CGContext(data: nil, width: 1, height: 1, bitsPerComponent: 8, bytesPerRow: 4,
                                              space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue))
        context.draw(background, in: CGRect(x: 0, y: 0, width: 1, height: 1))
        let components = try XCTUnwrap(context.data?.assumingMemoryBound(to: UInt8.self))
        XCTAssertLessThan(max(components[0], components[1], components[2]), 100, "The status-area surface must render dark.")
        attachScreenshot("iPhone-Codes-AX5-Dark", image: image)
        code.tap()
        XCTAssertEqual(code.value as? String, "已拷贝")

        app.terminate()
        let login = try launch(on: .phone, arguments: accessibilityArguments + ["--fixture-login"])
        let email = login.textFields["login.email"]
        XCTAssertTrue(email.waitForExistence(timeout: 5))
        email.tap()
        email.typeText("studio@example.com\n")
        login.secureTextFields["login.password"].typeText("fixture-only\n")
        let verification = login.textFields["twofactor.code"]
        XCTAssertTrue(verification.waitForExistence(timeout: 5))
        verification.tap()
        verification.typeText("123456")
        XCTAssertGreaterThan(verification.frame.height, 90)
        XCTAssertEqual(login.textFields.matching(identifier: "twofactor.code").count, 1)
        XCTAssertTrue(login.buttons["twofactor.submit"].isEnabled)
        let keyboard = login.keyboards.firstMatch
        XCTAssertTrue(keyboard.exists)
        let visibleCode = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            verification.frame.maxY <= keyboard.frame.minY + 2
        }, object: verification)
        XCTAssertEqual(XCTWaiter.wait(for: [visibleCode], timeout: 5), .completed,
                       "Every verification digit should remain above the keyboard.")
        attachScreenshot("iPhone-Login-Verification-AX5")
    }

    func testPhoneVoiceOverDescribesPickerWithoutSecrets() throws {
        let app = try launch(on: .phone, arguments: ["--fixture-autofill"])
        XCTAssertTrue(app.buttons["autofill.close"].waitForExistence(timeout: 5))
        let service = XCUIDevice.shared.voiceOverService
        let alreadyEnabled = service.isEnabled
        if !alreadyEnabled { try service.enable() }
        defer { if !alreadyEnabled { try? service.disable() } }
        var spoken = try service.currentSpeech().utterance
        for _ in 0..<18 where !spoken.contains("demo@example.com") {
            spoken += "\n" + (try service.moveForward().utterance)
        }
        XCTAssertTrue(spoken.contains("demo@example.com"), "VoiceOver should reach the matching credential.")
        for segment in ["sample-user", "fixture-pass", "private-path", "fixture-token", "fragment"] {
            XCTAssertFalse(spoken.contains(segment))
        }
    }

    func testPhoneCreatingItemsOpensTheSavedDetailAndReturnsToItsParent() throws {
        let app = try launch(on: .phone)
        let home = app.buttons["vault.newItem"]
        XCTAssertTrue(home.waitForExistence(timeout: 7))
        home.tap()
        saveNamedItem("A new home item", in: app)
        checkCreatedDetail("A new home item", in: app)
        app.navigationBars.buttons.element(boundBy: 0).tap()
        XCTAssertTrue(home.waitForExistence(timeout: 5))
        let folder = app.buttons["vault.folder.work"]
        scrollTo(folder, in: app)
        folder.tap()
        let createInFolder = app.buttons["folder.newItem"]
        XCTAssertTrue(createInFolder.waitForExistence(timeout: 5))
        createInFolder.tap()
        saveNamedItem("A new folder item", in: app)
        checkCreatedDetail("A new folder item", in: app)
        app.navigationBars.buttons.element(boundBy: 0).tap()
        XCTAssertTrue(createInFolder.waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["vault.item.new-2"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["vault.item.new-1"].exists)
    }

    func testPhoneRowCopiesInlineAndOffersContextActions() throws {
        let app = try launch(on: .phone)
        let item = app.buttons["vault.item.sample-studio"]
        scrollTo(item, in: app)
        item.swipeLeft()
        let copy = app.buttons["vault.copyPassword.sample-studio"]
        XCTAssertTrue(copy.waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["vault.trash.sample-studio"].exists)
        copy.tap()
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        var copied = item.value as? String == "已拷贝"
        while !copied, ContinuousClock.now < deadline {
            copied = item.value as? String == "已拷贝"
        }
        XCTAssertTrue(copied, "The row must advertise copy feedback before its 1.6-second receipt expires.")
        XCTAssertFalse(item.label.contains("fixture-only"))
        XCTAssertFalse(app.staticTexts["fixture-only"].exists)
        let cleared = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value != %@", "已拷贝"), object: item)
        XCTAssertEqual(XCTWaiter.wait(for: [cleared], timeout: 4), .completed)
        item.press(forDuration: 0.7)
        XCTAssertTrue(app.buttons.matching(NSPredicate(format: "identifier == %@ OR label == %@", "vault.copyPassword.sample-studio", "拷贝密码")).firstMatch.waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons.matching(NSPredicate(format: "identifier == %@ OR label == %@", "vault.trash.sample-studio", "移到回收站")).firstMatch.exists)
    }

    func testPhoneReadFailureDoesNotImpersonateEmptyDataAndCanRetry() throws {
        let app = try launch(on: .phone, arguments: ["--fixture-read-failure"])
        let retry = app.buttons["vault.retry"].firstMatch
        XCTAssertTrue(retry.waitForExistence(timeout: 7))
        XCTAssertFalse(app.staticTexts["保险库为空"].exists)
        XCTAssertFalse(app.buttons["vault.filter.all"].exists)
        phoneSearchTab(in: app).tap()
        let field = app.searchFields.firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        field.typeText("Dropbox")
        XCTAssertTrue(retry.waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["没有结果"].exists)
        XCTAssertFalse(app.staticTexts["0 个结果"].exists)
        closePhoneSearch(in: app)
        XCTAssertTrue(app.buttons["vault.settings"].waitForExistence(timeout: 5))
        XCUIDevice.shared.press(.home)
        app.activate()
        retry.tap()
        XCTAssertTrue(app.buttons["vault.pinned.sample-design"].waitForExistence(timeout: 5))
        XCTAssertFalse(retry.exists)
    }

    func testPadCreationOutsideCurrentFilterSelectsTheSavedItem() throws {
        let app = try launch(on: .pad)
        let filter = app.cells.matching(NSPredicate(format: "label BEGINSWITH %@", "银行卡")).firstMatch
        if filter.exists {
            filter.tap()
        } else {
            let chip = app.buttons["vault.filter.cards"]
            XCTAssertTrue(chip.waitForExistence(timeout: 7))
            chip.tap()
        }
        let existingCard = app.descendants(matching: .any).matching(identifier: "pad.item.sample-card").firstMatch
        XCTAssertTrue(existingCard.waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["pad.item.sample-studio"].exists)
        app.buttons["pad.newItem"].tap()
        XCTAssertTrue(app.textFields["持卡人"].waitForExistence(timeout: 5))
        app.buttons["安全笔记"].firstMatch.tap()
        saveNamedItem("A new note from cards", in: app)
        checkCreatedDetail("A new note from cards", in: app)
        let newRow = app.descendants(matching: .any).matching(identifier: "pad.item.new-1").firstMatch
        XCTAssertTrue(newRow.waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["pad.item.sample-studio"].exists)
        XCTAssertGreaterThan(app.buttons["item.edit"].frame.midX, newRow.frame.maxX)
    }

    func testPadCloningAPinnedLoginSelectsAnUnpinnedCopyInAllItems() throws {
        let app = try launch(on: .pad)
        let toggle = app.buttons.matching(NSPredicate(format: "identifier ==[c] %@", "ToggleSidebar")).firstMatch
        XCTAssertTrue(toggle.waitForExistence(timeout: 7))
        let sidebarWasOpen = app.cells["tab.codes"].exists
        if sidebarWasOpen { toggle.tap() }
        defer { if sidebarWasOpen, !app.cells["tab.codes"].exists, toggle.isHittable { toggle.tap() } }
        let pinned = app.buttons["vault.filter.favorites"]
        XCTAssertTrue(pinned.waitForExistence(timeout: 5))
        pinned.tap()
        let original = app.buttons["pad.item.sample-design"]
        let nonFavorite = app.buttons["pad.item.sample-studio"]
        XCTAssertTrue(original.waitForExistence(timeout: 5))
        XCTAssertFalse(nonFavorite.exists)
        original.tap()
        let favorite = app.buttons["item.favorite"]
        XCTAssertTrue(favorite.wait(for: \.label, toEqual: "取消置顶", timeout: 5))
        XCTAssertTrue(app.staticTexts["通行密钥"].exists)
        app.buttons["item.more"].tap()
        app.buttons["克隆"].tap()
        let duplicate = app.buttons["pad.item.new-1"]
        XCTAssertTrue(duplicate.waitForExistence(timeout: 5))
        XCTAssertTrue(nonFavorite.exists)
        checkCreatedDetail("GitHub 副本", in: app)
        XCTAssertEqual(favorite.label, "置顶")
        XCTAssertFalse(app.staticTexts["通行密钥"].exists)
        XCTAssertTrue(original.exists)
    }

    private func saveNamedItem(_ name: String, in app: XCUIApplication) {
        let field = app.textFields["名称"].firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        field.tap()
        field.typeText(name)
        let save = app.buttons["item.save"]
        XCTAssertTrue(save.isEnabled)
        save.tap()
        XCTAssertTrue(save.waitForNonExistence(timeout: 5))
    }

    private func checkCreatedDetail(_ name: String, in app: XCUIApplication) {
        XCTAssertTrue(app.buttons["item.edit"].waitForExistence(timeout: 5))
        let title = app.staticTexts.matching(NSPredicate(format: "label == %@", name)).allElementsBoundByIndex
        XCTAssertTrue(title.contains { $0.isHittable && (UIDevice.current.userInterfaceIdiom != .pad || $0.frame.midX > app.frame.midX) })
    }

    private func checkEditor(in app: XCUIApplication, board: String) throws {
        let save = app.buttons["item.save"]
        XCTAssertTrue(save.waitForExistence(timeout: 5))
        XCTAssertFalse(save.isEnabled)
        for kind in ["登录", "银行卡", "身份", "安全笔记", "SSH 密钥"] {
            XCTAssertTrue(app.buttons[kind].exists, "Missing item type: \(kind)")
        }
        attachScreenshot(board)
        app.buttons["银行卡"].tap()
        XCTAssertTrue(app.textFields["持卡人"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.textFields["用户名"].exists)
        app.buttons["item.cancel"].tap()
        XCTAssertTrue(save.waitForNonExistence(timeout: 5))
    }

    private func launch(on idiom: UIUserInterfaceIdiom, arguments: [String] = []) throws -> XCUIApplication {
        try XCTSkipUnless(UIDevice.current.userInterfaceIdiom == idiom, "Run on the matching simulator family.")
        XCUIDevice.shared.orientation = idiom == .pad ? .landscapeLeft : .portrait
        let app = XCUIApplication()
        app.launchArguments = arguments
        app.launch()
        return app
    }

    private func phoneSearchTab(in app: XCUIApplication) -> XCUIElement {
        app.tabBars.buttons.matching(NSPredicate(format: "label IN %@", ["搜索", "Search"])).firstMatch
    }

    private func padTab(_ title: String, identifier: String, in app: XCUIApplication) -> XCUIElement {
        let nativeTab = app.tabBars.buttons[title]
        if nativeTab.exists { return nativeTab }
        let tab = NSPredicate(format: "identifier == %@ OR label == %@", identifier, title)
        let sidebarTab = app.cells.matching(tab).firstMatch
        if sidebarTab.exists { return sidebarTab }
        return app.buttons.matching(tab).firstMatch
    }

    @discardableResult private func setPadSidebar(expanded: Bool, in app: XCUIApplication,
                                                  file: StaticString = #filePath, line: UInt = #line) -> Bool {
        let toggle = app.buttons.matching(NSPredicate(format: "identifier ==[c] %@", "ToggleSidebar")).firstMatch
        XCTAssertTrue(toggle.wait(for: \.isHittable, toEqual: true, timeout: 7), file: file, line: line)
        let sidebarTab = app.cells["tab.codes"]
        let wasExpanded = sidebarTab.exists
        if wasExpanded != expanded { toggle.tap() }
        if expanded {
            XCTAssertTrue(sidebarTab.wait(for: \.isHittable, toEqual: true, timeout: 5), file: file, line: line)
        } else {
            XCTAssertTrue(sidebarTab.waitForNonExistence(timeout: 5), file: file, line: line)
            XCTAssertTrue(padTab("验证码", identifier: "tab.codes", in: app).wait(for: \.isHittable, toEqual: true, timeout: 5),
                          file: file, line: line)
        }
        return wasExpanded
    }

    private func closePhoneSearch(in app: XCUIApplication) {
        let close = app.buttons.matching(NSPredicate(format: "label IN %@", ["关闭", "取消", "Close", "Cancel"])).firstMatch
        XCTAssertTrue(close.waitForExistence(timeout: 5))
        close.tap()
    }

    private func assertInLowerHalf(_ element: XCUIElement, in app: XCUIApplication,
                                   file: StaticString = #filePath, line: UInt = #line) {
        let keyboard = app.keyboards.firstMatch
        let bottom = keyboard.exists ? keyboard.frame.minY : app.frame.maxY
        let availableMidpoint = (app.frame.minY + bottom) / 2
        XCTAssertGreaterThan(element.frame.midY, availableMidpoint, file: file, line: line)
    }

    private func scrollTo(_ element: XCUIElement, in app: XCUIApplication) {
        func comfortablyVisible() -> Bool {
            guard element.exists, element.isHittable else { return false }
            let tabBar = app.tabBars.firstMatch
            let lowerEdge = tabBar.exists ? tabBar.frame.minY : app.frame.maxY
            return element.frame.minY > app.frame.minY + 72 && element.frame.maxY < lowerEdge - 8
        }
        for _ in 0..<6 {
            if comfortablyVisible() { return }
            if element.exists, element.frame.midY < app.frame.midY { app.swipeDown() }
            else { app.swipeUp() }
        }
        XCTAssertTrue(comfortablyVisible())
    }

    private func attachScreenshot(_ name: String, image: XCUIScreenshot? = nil) {
        let attachment = XCTAttachment(screenshot: image ?? XCUIScreen.main.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
