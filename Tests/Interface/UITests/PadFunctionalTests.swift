import UIKit
import XCTest

@MainActor
final class PadFunctionalTests: XCTestCase {
    private var app: XCUIApplication!

    override func setUpWithError() throws {
        try super.setUpWithError()
        continueAfterFailure = false
        try XCTSkipUnless(UIDevice.current.userInterfaceIdiom == .pad, "Run on iPad.")
        XCUIDevice.shared.orientation = .landscapeLeft
    }

    func testLoginChallengeAndManualUnlockReturnToVault() {
        launch(["--fixture-login"])
        let email = app.textFields["login.email"]
        let login = app.buttons["login.submit"]
        XCTAssertTrue(email.waitForExistence(timeout: 5))
        XCTAssertFalse(login.isEnabled)
        enter("studio@example.com", into: email)
        XCTAssertFalse(login.isEnabled)
        enter("fixture-only", into: app.secureTextFields["login.password"])
        XCTAssertTrue(login.isEnabled)
        tap(login)

        let code = app.textFields["twofactor.code"]
        XCTAssertTrue(code.waitForExistence(timeout: 5))
        dismissChallengeKeyboard()
        tapCenter(app.segmentedControls.buttons["邮件"])
        XCTAssertTrue(app.staticTexts["输入邮件中的 6 位验证码。"].waitForExistence(timeout: 5))
        tapCenter(app.buttons["重新发送邮件"])
        XCTAssertTrue(app.staticTexts["已请求发送验证码邮件"].waitForExistence(timeout: 5))
        let verify = app.buttons["twofactor.submit"]
        enter("12345", into: code)
        XCTAssertFalse(verify.isEnabled)
        code.typeText("6")
        XCTAssertTrue(verify.isEnabled)
        dismissChallengeKeyboard()
        tapCenter(verify)

        let row = app.buttons["pad.item.sample-studio"]
        XCTAssertTrue(row.waitForExistence(timeout: 7))
        XCTAssertFalse(code.exists)
        closeSidebar()
        openSettings()
        tapCenter(app.buttons["立即锁定"])
        let password = app.secureTextFields["unlock.password"]
        let unlock = app.buttons["unlock.submit"]
        XCTAssertTrue(password.waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["studio@example.com"].waitForExistence(timeout: 5))
        XCTAssertFalse(row.exists)
        XCTAssertFalse(unlock.isEnabled)
        enter("fixture-only", into: password)
        XCTAssertTrue(unlock.isEnabled)
        tap(unlock)
        XCTAssertTrue(row.waitForExistence(timeout: 7))
        XCTAssertFalse(password.exists)
    }

    func testSendCreateEditFilterAndDelete() {
        launch(["--fixture-sends"])
        closeSidebar()
        tap(tab("Send"))
        let preview = button(startingWith: "Prototype preview")
        let handoff = button(startingWith: "Design handoff")
        let all = button(startingWith: "全部")
        let files = button(startingWith: "文件")
        let texts = button(startingWith: "文本")
        XCTAssertTrue(handoff.waitForExistence(timeout: 5))
        checkSendCounts([3, 2, 1])
        tap(files)
        XCTAssertTrue(preview.wait(for: \.isSelected, toEqual: true, timeout: 5))
        XCTAssertFalse(handoff.exists)
        XCTAssertTrue(app.buttons["拷贝文件名"].waitForExistence(timeout: 5))

        let name = app.textFields["send.name"]
        let body = app.textViews["send.text"]
        let save = app.buttons["send.create"]
        tap(app.buttons["send.new"])
        XCTAssertTrue(save.waitForExistence(timeout: 5))
        XCTAssertFalse(save.isEnabled)
        enter("iPad handoff", into: name)
        XCTAssertFalse(save.isEnabled)
        enter("Review text", into: body)
        XCTAssertTrue(save.isEnabled)
        saveSendWithKeyboardVisible(save)

        let created = button(startingWith: "iPad handoff")
        let link = app.buttons["拷贝共享链接"]
        XCTAssertTrue(created.wait(for: \.isSelected, toEqual: true, timeout: 5))
        XCTAssertTrue(all.isSelected)
        XCTAssertTrue(link.wait(for: \.isHittable, toEqual: true, timeout: 5))
        XCTAssertGreaterThan(link.frame.midX, created.frame.maxX)
        checkSendCounts([4, 3, 1])

        let edit = app.buttons["编辑"]
        tap(edit)
        XCTAssertTrue(body.waitForExistence(timeout: 5))
        XCTAssertEqual(body.value as? String, "Review text")
        name.coordinate(withNormalizedOffset: CGVector(dx: 0.98, dy: 0.5)).tap()
        name.typeText(" updated")
        XCTAssertEqual(name.value as? String, "iPad handoff updated")
        saveSendWithKeyboardVisible(save)
        let updated = button(startingWith: "iPad handoff updated")
        XCTAssertTrue(updated.wait(for: \.isSelected, toEqual: true, timeout: 5))
        XCTAssertTrue(app.staticTexts["iPad handoff updated"].waitForExistence(timeout: 5))
        tap(files)
        XCTAssertTrue(preview.wait(for: \.isSelected, toEqual: true, timeout: 5))
        XCTAssertFalse(updated.exists)
        tap(texts)
        tap(updated)
        XCTAssertFalse(preview.exists)

        let more = app.buttons["更多"].firstMatch
        let deleteCommand = app.buttons["删除…"]
        let warning = app.staticTexts["链接会立即失效，接收者将无法再打开。"]
        let confirmation = app.sheets.firstMatch
        tap(more)
        tap(deleteCommand)
        XCTAssertTrue(warning.waitForExistence(timeout: 5))
        let cancel = confirmation.buttons["取消"]
        if cancel.exists { tap(cancel) }
        else {
            XCTAssertTrue(app.otherElements["PopoverDismissRegion"].exists)
            app.coordinate(withNormalizedOffset: .zero)
                .withOffset(CGVector(dx: app.frame.midX, dy: confirmation.frame.minY - 20)).tap()
        }
        XCTAssertTrue(warning.waitForNonExistence(timeout: 5))
        XCTAssertTrue(updated.isHittable)
        checkSendCounts([4, 3, 1])

        tap(updated)
        tap(more)
        tap(deleteCommand)
        XCTAssertTrue(warning.waitForExistence(timeout: 5))
        tap(confirmation.buttons["删除"])
        XCTAssertTrue(updated.waitForNonExistence(timeout: 5))
        checkSendCounts([3, 2, 1])
        tap(all)
        XCTAssertTrue(preview.waitForExistence(timeout: 5))
        XCTAssertFalse(created.exists)
    }

    func testGeneratorProducesAllThreeModesAndClearsTheirHistory() {
        launch()
        closeSidebar()
        tap(tab("生成器"))
        let modes = app.segmentedControls.firstMatch
        let generate = app.buttons["重新生成"]
        let length = app.sliders["密码长度"]
        XCTAssertTrue(length.waitForExistence(timeout: 5))
        let initialLength = length.value as? String
        length.adjust(toNormalizedSliderPosition: 0.75)
        let adjustedLength = length.value as? String
        XCTAssertNotNil(adjustedLength)
        XCTAssertNotEqual(initialLength, adjustedLength)
        tap(generate)

        tap(modes.buttons["口令"])
        let capitals = app.switches.matching(NSPredicate(format: "label BEGINSWITH %@", "首字母大写")).firstMatch
        let initialCapitals = toggleAndReadPreviousValue(capitals)
        let adjustedCapitals = capitals.value as? String
        XCTAssertNotEqual(initialCapitals, adjustedCapitals)
        tap(generate)

        tap(modes.buttons["用户名"])
        let base = app.textFields["基础名称"]
        enter("pad", into: base)
        let enteredBase = base.value as? String ?? ""
        XCTAssertTrue(enteredBase.contains("pad"))
        dismissKeyboard()
        tap(generate)
        let aliasPattern = NSRegularExpression.escapedPattern(for: enteredBase) + #"\+[a-z2-9]{4}@icloud\.com"#
        let alias = app.staticTexts.matching(NSPredicate(format: "label MATCHES %@", aliasPattern)).firstMatch
        XCTAssertTrue(alias.waitForExistence(timeout: 5))

        tap(modes.buttons["密码"])
        XCTAssertEqual(length.value as? String, adjustedLength)
        tap(modes.buttons["口令"])
        XCTAssertEqual(capitals.value as? String, adjustedCapitals)
        let history = app.buttons["生成历史"]
        tap(history)
        for kind in ["密码", "口令", "用户名"] {
            XCTAssertTrue(app.buttons["拷贝\(kind)"].firstMatch.waitForExistence(timeout: 5))
        }
        tap(app.buttons["清除"])
        let empty = app.staticTexts["没有生成历史"]
        XCTAssertTrue(empty.waitForExistence(timeout: 5))
        tap(app.buttons["完成"])
        tap(history)
        XCTAssertTrue(empty.waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["清除"].isEnabled)
    }

    func testAppearancePreferenceUpdatesTheVaultAndSurvivesRelaunch() {
        launch()
        closeSidebar()
        let row = app.buttons["pad.item.sample-studio"]
        XCTAssertTrue(row.waitForExistence(timeout: 5))
        openAppearanceSettings()
        let usernames = app.switches["列表中显示用户名"]
        let initial = toggleAndReadPreviousValue(usernames)
        let adjusted = initial == "1" ? "0" : "1"
        checkToggleValue(usernames, equals: adjusted)
        tapCenter(app.buttons["settings.back"])
        checkVaultUsername(row, visible: adjusted == "1")

        app.terminate()
        app.launch()
        closeSidebar()
        checkVaultUsername(row, visible: adjusted == "1")
        openAppearanceSettings()
        checkToggleValue(usernames, equals: adjusted)
        toggleAndReadPreviousValue(usernames)
        checkToggleValue(usernames, equals: initial)
        tapCenter(app.buttons["settings.back"])
        checkVaultUsername(row, visible: initial == "1")
    }

    func testEmptySearchClearsAndRoutesFromCodesToTheVaultDetail() {
        launch()
        closeSidebar()
        let codes = tab("验证码")
        tap(codes)
        let code = app.buttons["codes.copy.sample-design"]
        XCTAssertTrue(code.waitForExistence(timeout: 5))
        let open = app.buttons["search.open"]
        let query = app.textFields["search.field"]
        tap(open)
        enter("zymurgy-not-in-fixture", into: query)
        XCTAssertTrue(app.staticTexts["0 个结果"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["没有结果"].exists)
        XCTAssertFalse(code.isEnabled)
        tap(app.buttons["清除搜索"])
        XCTAssertTrue(app.staticTexts["全部条目"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["没有结果"].exists)
        tap(app.buttons["search.close"])
        XCTAssertTrue(query.waitForNonExistence(timeout: 5))
        XCTAssertTrue(app.keyboards.firstMatch.waitForNonExistence(timeout: 5))
        XCTAssertTrue(code.wait(for: \.isHittable, toEqual: true, timeout: 5))
        XCTAssertTrue(codes.isSelected)

        tap(open)
        enter("GitHub", into: query)
        XCTAssertTrue(app.staticTexts["1 个结果"].waitForExistence(timeout: 5))
        tap(app.buttons["vault.item.sample-design"])
        let row = app.buttons["pad.item.sample-design"]
        let detail = app.buttons["item.edit"]
        XCTAssertTrue(row.wait(for: \.isSelected, toEqual: true, timeout: 5))
        XCTAssertTrue(detail.wait(for: \.isHittable, toEqual: true, timeout: 5))
        XCTAssertGreaterThan(detail.frame.midX, row.frame.maxX)
        XCTAssertTrue(tab("保险库").isSelected)
        XCTAssertFalse(query.exists)
    }

    private func launch(_ arguments: [String] = []) {
        app = XCUIApplication()
        app.launchArguments = arguments
        app.launch()
    }

    private func closeSidebar() {
        let toggle = app.buttons.matching(NSPredicate(format: "identifier ==[c] %@", "ToggleSidebar")).firstMatch
        XCTAssertTrue(toggle.wait(for: \.isHittable, toEqual: true, timeout: 7))
        let sidebar = app.cells["tab.codes"]
        if sidebar.exists { toggle.tap() }
        XCTAssertTrue(sidebar.waitForNonExistence(timeout: 5))
        XCTAssertTrue(tab("验证码").wait(for: \.isHittable, toEqual: true, timeout: 5))
    }

    private func tab(_ title: String) -> XCUIElement {
        let native = app.tabBars.buttons[title]
        return native.exists ? native : app.buttons[title].firstMatch
    }

    private func openSettings() {
        tap(app.buttons["navigation.settings"].firstMatch)
        XCTAssertTrue(app.buttons["settings.back"].waitForExistence(timeout: 5))
    }

    private func openAppearanceSettings() {
        openSettings()
        tapCenter(app.buttons["外观"])
    }

    private func checkVaultUsername(_ row: XCUIElement, visible: Bool, line: UInt = #line) {
        let matchingRow = app.buttons.matching(identifier: row.identifier).matching(
            NSPredicate(format: visible ? "label CONTAINS %@" : "NOT (label CONTAINS %@)", "studio@example.com")
        ).firstMatch
        XCTAssertTrue(matchingRow.waitForExistence(timeout: 5), line: line)
    }

    @discardableResult private func toggleAndReadPreviousValue(_ toggle: XCUIElement, line: UInt = #line) -> String {
        XCTAssertTrue(toggle.waitForExistence(timeout: 5), line: line)
        let initial = toggle.value as? String ?? ""
        XCTAssertTrue(["0", "1"].contains(initial), line: line)
        let control = toggle.switches.firstMatch
        if control.exists { tapCenter(control, line: line) }
        else { tap(toggle, line: line) }
        return initial
    }

    private func checkToggleValue(_ toggle: XCUIElement, equals expected: String, line: UInt = #line) {
        let changed = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value == %@", expected), object: toggle)
        XCTAssertEqual(XCTWaiter.wait(for: [changed], timeout: 5), .completed, line: line)
    }

    private func button(startingWith label: String) -> XCUIElement {
        app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", label)).firstMatch
    }

    private func checkSendCounts(_ expected: [Int], line: UInt = #line) {
        for (label, count) in zip(["全部", "文本", "文件"], expected) {
            let filter = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@ AND label ENDSWITH %@", label, String(count))).firstMatch
            XCTAssertTrue(filter.waitForExistence(timeout: 5), "Expected \(label) to show \(count).", line: line)
        }
    }

    private func tap(_ element: XCUIElement, line: UInt = #line) {
        XCTAssertTrue(element.isHittable || element.wait(for: \.isHittable, toEqual: true, timeout: 5), "Cannot tap \(element).", line: line)
        element.tap()
    }

    private func tapCenter(_ element: XCUIElement, line: UInt = #line) {
        XCTAssertTrue(element.waitForExistence(timeout: 5), line: line)
        let point = CGPoint(x: element.frame.midX, y: element.frame.midY)
        let window = app.frame
        XCTAssertTrue(window.contains(point), "Cannot tap \(element) outside the window.", line: line)
        app.coordinate(withNormalizedOffset: .zero)
            .withOffset(CGVector(dx: point.x - window.minX, dy: point.y - window.minY)).tap()
    }

    private func enter(_ text: String, into field: XCUIElement, line: UInt = #line) {
        tap(field, line: line)
        field.typeText(text)
    }

    private func saveSendWithKeyboardVisible(_ save: XCUIElement, line: UInt = #line) {
        let keyboard = app.keyboards.firstMatch
        XCTAssertTrue(keyboard.exists && keyboard.frame.intersects(app.frame), line: line)
        XCTAssertLessThan(save.frame.maxY, keyboard.frame.minY, line: line)
        XCTAssertTrue(save.isEnabled, line: line)
        tapCenter(save, line: line)
        XCTAssertTrue(save.waitForNonExistence(timeout: 5), line: line)
    }

    private func dismissKeyboard(line: UInt = #line) {
        let dismiss = app.keyboards.buttons["隐藏键盘"].firstMatch
        if dismiss.isHittable {
            dismiss.tap()
            XCTAssertTrue(dismiss.wait(for: \.isHittable, toEqual: false, timeout: 5), line: line)
        }
    }

    private func dismissChallengeKeyboard() {
        dismissKeyboard()
        app.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.2)).tap()
    }
}
