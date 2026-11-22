import UIKit
import XCTest

@MainActor
final class NavigationTests: XCTestCase {
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    func testPhoneSettingsAndBottomSearchFromEachTool() throws {
        let app = try launch(on: .phone)
        let settings = app.buttons["vault.settings"]
        XCTAssertTrue(settings.waitForExistence(timeout: 7))
        XCTAssertEqual(settings.label, "设置")
        XCTAssertFalse(app.navigationBars.buttons["搜索"].exists)
        attachScreenshot("iphone-vault")
        settings.tap()
        XCTAssertTrue(app.navigationBars["设置"].waitForExistence(timeout: 5))
        app.navigationBars.buttons.element(boundBy: 0).tap()

        let search = phoneSearchTab(in: app)
        for title in ["保险库", "验证码", "Send", "生成器"] {
            let tab = app.tabBars.buttons[title]
            tab.tap()
            XCTAssertTrue(search.isHittable)
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
        attachScreenshot("iphone-detail")
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
        item.swipeLeft()
        app.buttons["vault.trash.sample-studio"].tap()
        let undo = app.buttons["vault.undo"]
        XCTAssertTrue(undo.waitForExistence(timeout: 3))
        undo.tap()
        XCTAssertTrue(item.waitForExistence(timeout: 5))
        item.swipeLeft()
        app.buttons["vault.trash.sample-studio"].tap()

        let trash = app.buttons["vault.trash"]
        scrollTo(trash, in: app)
        trash.tap()
        let discarded = app.descendants(matching: .any).matching(identifier: "trash.item.sample-studio").firstMatch
        XCTAssertTrue(discarded.waitForExistence(timeout: 5))
        discarded.swipeLeft()
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
        attachScreenshot("iphone-unlock")
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
        app.swipeUp()
        app.swipeUp()
        XCTAssertFalse(first.isHittable)
        XCTAssertTrue(close.isHittable)
        attachScreenshot("iphone-autofill")
        close.tap()
        XCTAssertTrue(app.buttons["vault.settings"].waitForExistence(timeout: 5))
    }

    func testPhoneSendDraftValidatesAndCreatesAnItem() throws {
        let app = try launch(on: .phone, arguments: ["--fixture-sends"])
        let tab = app.tabBars.buttons["Send"]
        XCTAssertTrue(tab.waitForExistence(timeout: 7))
        tab.tap()
        app.buttons["send.new"].tap()
        let create = app.buttons["send.create"]
        XCTAssertTrue(create.waitForExistence(timeout: 5))
        XCTAssertFalse(create.isEnabled)
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
        attachScreenshot("iphone-send-detail")
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

    func testPadVaultSplitViewAndBottomSearch() throws {
        let app = try launch(on: .pad)
        let listRow = app.descendants(matching: .any).matching(identifier: "pad.item.sample-studio").firstMatch
        XCTAssertTrue(listRow.waitForExistence(timeout: 7))
        listRow.tap()
        let detail = app.buttons["item.copyPassword"]
        XCTAssertTrue(detail.waitForExistence(timeout: 5))
        XCTAssertGreaterThan(detail.frame.midX, listRow.frame.midX)
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
        open.tap()
        XCTAssertTrue(query.waitForExistence(timeout: 5))
        query.tap()
        query.typeText("Dropbox")
        let result = app.buttons["vault.item.sample-studio"]
        XCTAssertTrue(result.waitForExistence(timeout: 5))
        result.tap()
        XCTAssertTrue(detail.waitForExistence(timeout: 5))
        attachScreenshot("ipad-search-detail")
    }

    func testPadCodesAndGeneratorHistory() throws {
        let app = try launch(on: .pad)
        let codes = padTab("验证码", identifier: "tab.codes", in: app)
        XCTAssertTrue(codes.waitForExistence(timeout: 7))
        codes.tap()
        let code = app.buttons["codes.copy.sample-design"]
        XCTAssertTrue(code.waitForExistence(timeout: 5))
        XCTAssertTrue(code.isHittable)
        code.tap()
        attachScreenshot("ipad-codes")

        padTab("生成器", identifier: "tab.generator", in: app).tap()
        let generate = app.buttons["重新生成"]
        XCTAssertTrue(generate.waitForExistence(timeout: 5))
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
        return app.buttons.matching(NSPredicate(format: "identifier == %@ OR label == %@", identifier, title)).firstMatch
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
        guard !element.isHittable else { return }
        for _ in 0..<4 where !element.isHittable { app.swipeUp() }
        for _ in 0..<4 where !element.isHittable { app.swipeDown() }
        XCTAssertTrue(element.isHittable)
    }

    private func attachScreenshot(_ name: String) {
        let image = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        image.name = name
        image.lifetime = .keepAlways
        add(image)
    }
}
