import UIKit
import XCTest

@MainActor
final class NavigationTests: XCTestCase {
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    func testPhoneTabsSettingsAndSearch() throws {
        let app = try launch(on: .phone)
        let settings = app.navigationBars.buttons["设置"]
        XCTAssertTrue(settings.waitForExistence(timeout: 10))
        XCTAssertFalse(app.navigationBars.buttons.matching(NSPredicate(format: "label IN %@", ["搜索", "Search"])).firstMatch.exists)
        attachScreenshot("iphone-vault")
        settings.tap()
        let settingsBar = app.navigationBars["设置"]
        XCTAssertTrue(settingsBar.waitForExistence(timeout: 5))
        settingsBar.buttons.firstMatch.tap()

        for title in ["验证码", "发送", "保险库", "生成器"] {
            app.tabBars.buttons[title].tap()
            XCTAssertTrue(app.navigationBars[title].waitForExistence(timeout: 5))
        }
        let searchTab = app.tabBars.buttons.matching(NSPredicate(format: "label IN %@", ["搜索", "Search"])).firstMatch
        searchTab.tap()
        let search = app.searchFields.firstMatch
        XCTAssertTrue(search.waitForExistence(timeout: 5))
        XCTAssertEqual(app.searchFields.count, 1)
        // The Search tab should focus its field in one tap, not require a second tap.
        search.typeText("Dropbox")
        let result = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "Dropbox")).firstMatch
        XCTAssertTrue(result.waitForExistence(timeout: 5))
        app.buttons["关闭"].tap()
        XCTAssertTrue(app.tabBars.buttons["生成器"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.tabBars.buttons["生成器"].isSelected)
        XCTAssertFalse(app.keyboards.firstMatch.exists)
        searchTab.tap()
        XCTAssertTrue(search.waitForExistence(timeout: 5))
        search.typeText("Dropbox")
        XCTAssertTrue(result.waitForExistence(timeout: 5))
        result.tap()
        XCTAssertTrue(app.buttons["显示密码"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["复制密码"].isHittable)
        attachScreenshot("iphone-detail")
    }

    func testPhonePasswordUnlockSheet() throws {
        let app = try launch(on: .phone, arguments: ["--fixture-unlock"])
        let password = app.buttons["使用主密码解锁"]
        XCTAssertTrue(password.waitForExistence(timeout: 5))
        XCTAssertTrue(password.isHittable)
        attachScreenshot("iphone-unlock")
        password.tap()
        XCTAssertTrue(app.secureTextFields.firstMatch.waitForExistence(timeout: 5))
        app.buttons["取消"].tap()
        XCTAssertTrue(password.waitForExistence(timeout: 5))
    }

    func testPhoneAutoFillCancelAfterScrolling() throws {
        let app = try launch(on: .phone, arguments: ["--fixture-autofill"])
        let first = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "site-1.example.com")).firstMatch
        XCTAssertTrue(first.waitForExistence(timeout: 7))
        for value in ["demo@example.com", "工作账户", "密码"] { XCTAssertTrue(first.label.contains(value)) }
        for value in ["sample-user", "fixture-pass", "private-path", "fixture-token", "fragment"] {
            XCTAssertFalse(first.label.contains(value))
            XCTAssertFalse(app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", value)).firstMatch.exists)
        }
        let cancel = app.buttons["取消"]
        XCTAssertTrue(cancel.isHittable)
        app.swipeUp()
        app.swipeUp()
        XCTAssertFalse(first.isHittable)
        XCTAssertTrue(cancel.isHittable)
        attachScreenshot("iphone-autofill")
        cancel.tap()
        XCTAssertTrue(app.navigationBars.buttons["设置"].waitForExistence(timeout: 5))
    }

    func testPadSidebarChangesDetailAndTool() throws {
        let app = try launch(on: .pad)
        let sidebar = app.collectionViews.containing(.staticText, identifier: "过滤器").firstMatch
        let codes = sidebar.staticTexts["验证码"]
        XCTAssertTrue(codes.waitForExistence(timeout: 7))
        codes.tap()
        let copy = app.buttons["拷贝验证码"]
        XCTAssertTrue(copy.waitForExistence(timeout: 5))
        XCTAssertTrue(copy.isHittable)
        attachScreenshot("ipad-codes")
        sidebar.staticTexts["生成器"].tap()
        XCTAssertTrue(app.buttons["重新生成"].waitForExistence(timeout: 5))
    }

    private func launch(on idiom: UIUserInterfaceIdiom, arguments: [String] = []) throws -> XCUIApplication {
        try XCTSkipUnless(UIDevice.current.userInterfaceIdiom == idiom, "Run on the matching simulator family.")
        XCUIDevice.shared.orientation = idiom == .pad ? .landscapeLeft : .portrait
        let app = XCUIApplication()
        app.launchArguments = arguments
        app.launch()
        return app
    }

    private func attachScreenshot(_ name: String) {
        let image = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        image.name = name
        image.lifetime = .keepAlways
        add(image)
    }
}
