import UIKit
import XCTest

@MainActor
final class PhoneFunctionalTests: XCTestCase {
    private var app: XCUIApplication!

    override func setUpWithError() throws {
        try super.setUpWithError()
        continueAfterFailure = false
        try XCTSkipUnless(UIDevice.current.userInterfaceIdiom == .phone, "Run on iPhone.")
        XCUIDevice.shared.orientation = .portrait
        app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.buttons["vault.settings"].waitForExistence(timeout: 8))
    }

    func testLoginRoundTripAndExistingPasskeySurvivesEditing() {
        checkRoundTrip(kind: "登录", title: "A Login", field: "用户名", value: "reviewer")
        back()
        let existing = app.buttons["vault.pinned.sample-design"]
        reveal(existing, towardTop: true)
        existing.tap()
        XCTAssertTrue(app.staticTexts["GitHub"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["通行密钥"].waitForExistence(timeout: 5))
        tap("item.edit")
        let name = app.textFields["名称"]
        name.tap()
        name.typeText(" Review")
        tap("item.save")
        XCTAssertTrue(app.staticTexts["GitHub Review"].waitForExistence(timeout: 5))
        back()
        reveal(existing, towardTop: true)
        existing.tap()
        XCTAssertTrue(app.staticTexts["GitHub Review"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["通行密钥"].exists)
        XCTAssertTrue(app.buttons["item.copyCode"].exists)
        XCTAssertTrue(app.buttons["item.copyPassword"].exists)
    }

    func testEachPinnedTileOpensItsOwnRecord() {
        attachScreenshot("Functional-iPhone-Pinned")
        for (suffix, title) in [("sample", "Apple 账户"), ("creative", "Figma"), ("design", "GitHub"), ("home", "Google")] {
            let tile = app.buttons["vault.pinned.sample-" + suffix]
            XCTAssertTrue(tile.wait(for: \.isHittable, toEqual: true, timeout: 5))
            XCTAssertTrue(tile.label.contains(title))
            XCTAssertGreaterThanOrEqual(tile.frame.width, 44)
            XCTAssertGreaterThanOrEqual(tile.frame.height, 44)
            tile.tap()
            XCTAssertTrue(app.buttons["item.edit"].waitForExistence(timeout: 5))
            XCTAssertTrue(app.staticTexts[title].waitForExistence(timeout: 5), "The opened detail must match the tapped pinned tile: \(title).")
            back()
        }
    }

    func testCardRoundTrip() {
        checkRoundTrip(kind: "银行卡", title: "A Card", field: "持卡人", value: "Morgan", detail: "item.copy.holder")
    }

    func testIdentityRoundTrip() {
        checkRoundTrip(kind: "身份", title: "A Identity", field: "姓氏", value: "Lane", detail: "item.copy.lastName")
    }

    func testNoteRoundTrip() {
        checkRoundTrip(kind: "安全笔记", title: "A Note", field: "正文", value: "Review note")
    }

    func testSSHKeyRoundTrip() {
        let title = "A SSH"
        let privateMaterial = "fixture-private-material"
        let publicMaterial = "fixture-public-material"
        let fingerprint = "fixture-fingerprint"
        let save = app.buttons["item.save"]
        tap("vault.newItem")
        tap("SSH 密钥")
        input("名称", title)
        let hint = app.staticTexts["SSH 密钥必须包含私钥、公钥和指纹。"]
        reveal(hint)
        XCTAssertFalse(save.isEnabled)
        reveal(app.buttons["显示私钥"], towardTop: true)
        tap("显示私钥")
        input("私钥", privateMaterial)
        XCTAssertFalse(save.isEnabled)
        input("公钥", publicMaterial)
        XCTAssertFalse(save.isEnabled)
        input("指纹", fingerprint)
        XCTAssertTrue(save.isEnabled)
        tap("item.save")
        XCTAssertTrue(app.staticTexts[title].waitForExistence(timeout: 5))
        tap("item.edit")
        let name = editorField("名称")
        reveal(name, towardTop: true)
        name.tap()
        name.typeText(" Updated")
        tap("item.save")
        let edited = title + " Updated"
        XCTAssertTrue(app.staticTexts[edited].waitForExistence(timeout: 5))
        back()
        let record = app.buttons["vault.item.new-1"]
        reveal(record)
        XCTAssertTrue(record.label.contains(edited))
        record.tap()
        XCTAssertTrue(app.buttons["item.copy.fingerprint"].waitForExistence(timeout: 5))
        tap("item.edit")
        reveal(app.buttons["显示私钥"])
        tap("显示私钥")
        XCTAssertEqual(editorField("私钥").value as? String, privateMaterial)
        reveal(editorField("公钥"))
        XCTAssertEqual(editorField("公钥").value as? String, publicMaterial)
        reveal(editorField("指纹"))
        XCTAssertEqual(editorField("指纹").value as? String, fingerprint)
        tap("item.cancel")
    }

    func testFolderRenameAndDeletionLeavesContainedItemUnfiled() {
        tap("新建文件夹")
        let alert = app.alerts.firstMatch
        let save = alert.buttons["存储"]
        XCTAssertFalse(save.isEnabled)
        alert.textFields.firstMatch.tap()
        alert.textFields.firstMatch.typeText("Pilot")
        save.tap()
        let folder = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Pilot")).firstMatch
        reveal(folder)
        folder.tap()
        XCTAssertTrue(app.staticTexts["此文件夹为空"].waitForExistence(timeout: 5))
        tap("folder.newItem")
        input("名称", "A Folder Item")
        tap("item.save")
        XCTAssertTrue(app.staticTexts["A Folder Item"].waitForExistence(timeout: 5))
        back()
        let record = app.buttons["vault.item.new-1"]
        XCTAssertTrue(record.waitForExistence(timeout: 5))
        tap("文件夹操作")
        tap("重命名")
        let folderName = alert.textFields.firstMatch
        XCTAssertEqual(folderName.value as? String, "Pilot")
        folderName.tap()
        folderName.typeText(" Renamed")
        save.tap()
        XCTAssertTrue(app.navigationBars["Pilot Renamed"].waitForExistence(timeout: 5))
        tap("文件夹操作")
        tap("删除文件夹")
        let consequence = alert.staticTexts.matching(NSPredicate(format: "label CONTAINS %@ AND label CONTAINS %@", "1 个条目", "无文件夹")).firstMatch
        XCTAssertTrue(consequence.waitForExistence(timeout: 5))
        alert.buttons["取消"].tap()
        XCTAssertTrue(record.waitForExistence(timeout: 5))
        tap("文件夹操作")
        tap("删除文件夹")
        alert.buttons["删除文件夹"].tap()
        let unfiled = app.buttons["vault.folder.unfiled"]
        reveal(unfiled)
        XCTAssertFalse(folder.exists)
        unfiled.tap()
        XCTAssertTrue(record.waitForExistence(timeout: 5))
        record.tap()
        XCTAssertTrue(app.staticTexts["A Folder Item"].waitForExistence(timeout: 5))
    }

    func testPinArchiveRestoreAndConfirmedTrashRemoval() {
        let pinned = app.buttons["vault.pinned.sample-design"]
        pinned.tap()
        XCTAssertTrue(app.staticTexts["GitHub"].waitForExistence(timeout: 5))
        let favorite = app.buttons["item.favorite"]
        XCTAssertEqual(favorite.label, "取消置顶")
        favorite.tap()
        XCTAssertTrue(favorite.wait(for: \.label, toEqual: "置顶", timeout: 5))
        back()
        XCTAssertTrue(pinned.waitForNonExistence(timeout: 5))
        let item = app.buttons["vault.item.sample-design"]
        reveal(item)
        item.tap()
        favorite.tap()
        XCTAssertTrue(favorite.wait(for: \.label, toEqual: "取消置顶", timeout: 5))
        back()
        reveal(pinned, towardTop: true)
        pinned.tap()
        tap("item.more")
        tap("item.archive")
        XCTAssertTrue(app.buttons["vault.settings"].waitForExistence(timeout: 5))
        XCTAssertTrue(pinned.waitForNonExistence(timeout: 5))
        let archive = app.buttons["vault.archive"]
        reveal(archive)
        archive.tap()
        tap("取消归档“GitHub”")
        back()
        reveal(pinned, towardTop: true)
        pinned.tap()
        tap("item.more")
        tap("item.trash")
        XCTAssertTrue(app.buttons["vault.settings"].waitForExistence(timeout: 5))
        XCTAssertTrue(pinned.waitForNonExistence(timeout: 5))
        let trash = app.buttons["vault.trash"]
        reveal(trash)
        trash.tap()
        let discarded = app.descendants(matching: .any).matching(identifier: "trash.item.sample-design").firstMatch
        XCTAssertTrue(discarded.waitForExistence(timeout: 5))
        discarded.swipeLeft()
        XCTAssertTrue(app.buttons["trash.delete.sample-design"].waitForExistence(timeout: 5))
        attachScreenshot("Functional-iPhone-Trash-Swipe")
        tap("trash.delete.sample-design")
        XCTAssertTrue(app.staticTexts["永久删除“GitHub”？"].waitForExistence(timeout: 5))
        attachScreenshot("Functional-iPhone-Trash-Confirmation")
        cancelConfirmation()
        XCTAssertTrue(discarded.wait(for: \.isHittable, toEqual: true, timeout: 5))
        attachScreenshot("Functional-iPhone-Trash-Cancelled")
        tap("trash.empty")
        XCTAssertTrue(app.staticTexts["永久删除回收站中的 1 个条目？"].waitForExistence(timeout: 5))
        tap("永久删除")
        XCTAssertTrue(app.staticTexts["回收站是空的"].waitForExistence(timeout: 5))
        XCTAssertFalse(discarded.exists)
        back()
        reveal(trash)
        trash.tap()
        XCTAssertTrue(app.staticTexts["回收站是空的"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["trash.empty"].isEnabled)
    }

    func testSettingsPreferenceAndSessionTransitions() {
        tap("vault.settings")
        let timeout = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "自动锁定")).firstMatch
        reveal(timeout)
        timeout.tap()
        tap("15 分钟后")
        back()
        tap("vault.settings")
        reveal(timeout)
        XCTAssertTrue(timeout.label.contains("15 分钟后") || (timeout.value as? String)?.contains("15 分钟后") == true)
        let lock = app.buttons["立即锁定"]
        reveal(lock)
        lock.tap()
        let password = app.secureTextFields["unlock.password"]
        XCTAssertTrue(password.waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["unlock.submit"].isEnabled)
        password.tap()
        password.typeText("fixture-only")
        tap("unlock.submit")
        tap("vault.settings")
        let logout = app.buttons["退出登录"].firstMatch
        reveal(logout)
        logout.tap()
        cancelConfirmation()
        XCTAssertTrue(lock.waitForExistence(timeout: 5))
        logout.tap()
        let dialog = app.sheets.firstMatch
        XCTAssertTrue(dialog.buttons["退出登录"].waitForExistence(timeout: 5))
        dialog.buttons["退出登录"].tap()
        XCTAssertTrue(app.textFields["login.email"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["vault.settings"].exists)
    }

    func testExportRejectsIncorrectMasterPasswordAndClearsIt() {
        tap("vault.settings")
        let transfer = app.buttons["导入与导出"]
        reveal(transfer)
        transfer.tap()
        app.segmentedControls.buttons["导出"].tap()
        let password = app.secureTextFields.firstMatch
        let export = app.buttons["导出…"]
        XCTAssertFalse(export.isEnabled)
        password.tap()
        password.typeText("incorrect-fixture-password")
        reveal(export)
        export.tap()
        XCTAssertTrue(app.staticTexts["主密码不正确。"].waitForExistence(timeout: 5))
        XCTAssertFalse(export.isEnabled)
        XCTAssertFalse(app.staticTexts["保险库已导出。"].exists)
    }

    func testGeneratorModesKeepOptionsAndClearPopulatedHistory() {
        app.tabBars.buttons["生成器"].tap()
        let modes = app.segmentedControls.firstMatch
        XCTAssertTrue(modes.buttons["口令"].waitForExistence(timeout: 5))
        modes.buttons["口令"].tap()
        let capitals = app.switches.matching(NSPredicate(format: "label BEGINSWITH %@", "首字母大写")).firstMatch
        reveal(capitals)
        let before = capitals.value as? String
        XCTAssertNotNil(before)
        capitals.tap()
        let changed = capitals.value as? String
        XCTAssertNotEqual(before, changed)
        modes.buttons["用户名"].tap()
        XCTAssertTrue(app.textFields["基础名称"].waitForExistence(timeout: 5))
        tap("重新生成")
        modes.buttons["口令"].tap()
        XCTAssertEqual(capitals.value as? String, changed)
        tap("重新生成")
        tap("生成历史")
        XCTAssertTrue(app.buttons["拷贝口令"].firstMatch.waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["拷贝用户名"].firstMatch.exists)
        tap("清除")
        XCTAssertTrue(app.staticTexts["没有生成历史"].waitForExistence(timeout: 5))
        tap("完成")
        tap("生成历史")
        XCTAssertTrue(app.staticTexts["没有生成历史"].waitForExistence(timeout: 5))
    }

    private func checkRoundTrip(kind: String, title: String, field: String, value: String, detail: String? = nil) {
        tap("vault.newItem")
        if kind != "登录" { tap(kind) }
        XCTAssertFalse(app.buttons["item.save"].isEnabled)
        input("名称", title)
        input(field, value)
        tap("item.save")
        XCTAssertTrue(app.staticTexts[title].waitForExistence(timeout: 5))
        tap("item.edit")
        XCTAssertEqual(editorField(field).value as? String, value)
        let name = app.textFields["名称"]
        name.tap()
        name.typeText(" Updated")
        tap("item.save")
        let edited = title + " Updated"
        XCTAssertTrue(app.staticTexts[edited].waitForExistence(timeout: 5))
        back()
        let record = app.buttons["vault.item.new-1"]
        reveal(record)
        XCTAssertTrue(record.label.contains(edited))
        record.tap()
        if let detail { XCTAssertTrue(app.buttons[detail].waitForExistence(timeout: 5)) }
        tap("item.edit")
        XCTAssertEqual(editorField(field).value as? String, value)
        tap("item.cancel")
    }

    private func editorField(_ title: String) -> XCUIElement {
        app.descendants(matching: .any).matching(NSPredicate(format: "label == %@ AND (elementType == %d OR elementType == %d)", title,
            XCUIElement.ElementType.textField.rawValue, XCUIElement.ElementType.textView.rawValue)).firstMatch
    }

    private func input(_ title: String, _ value: String) {
        let field = editorField(title)
        reveal(field)
        field.tap()
        field.typeText(value)
    }

    private func tap(_ identifier: String) {
        let button = app.buttons[identifier].firstMatch
        XCTAssertTrue(button.wait(for: \.isHittable, toEqual: true, timeout: 5), "Missing button: \(identifier)")
        button.tap()
    }

    private func cancelConfirmation() {
        let sheet = app.sheets.firstMatch
        XCTAssertTrue(sheet.waitForExistence(timeout: 5))
        let cancel = sheet.buttons["取消"]
        if cancel.exists {
            cancel.tap()
        } else {
            let dismiss = app.otherElements["PopoverDismissRegion"]
            XCTAssertTrue(dismiss.exists)
            let sheetFrame = sheet.frame
            let outsideY = sheetFrame.midY < app.frame.midY ? sheetFrame.maxY + 44 : sheetFrame.minY - 44
            let outside = app.coordinate(withNormalizedOffset: .zero)
                .withOffset(CGVector(dx: app.frame.width / 2, dy: outsideY - app.frame.minY))
            outside.tap()
        }
        XCTAssertTrue(sheet.waitForNonExistence(timeout: 5))
    }

    private func back() {
        app.navigationBars.buttons.element(boundBy: 0).tap()
    }

    private func attachScreenshot(_ name: String) {
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    private func reveal(_ element: XCUIElement, towardTop: Bool = false,
                        file: StaticString = #filePath, line: UInt = #line) {
        for _ in 0..<7 {
            let exists = element.exists
            if exists, element.isHittable, element.frame.midY > app.frame.minY + 65 {
                let bottom = app.keyboards.firstMatch.exists ? app.keyboards.firstMatch.frame.minY : app.frame.maxY - 85
                if element.frame.midY < bottom - 4 { return }
            }
            if exists ? element.frame.midY < app.frame.midY : towardTop { app.swipeDown() }
            else { app.swipeUp() }
        }
        XCTAssertTrue(element.isHittable, "The requested control must be reachable by scrolling.", file: file, line: line)
    }
}
