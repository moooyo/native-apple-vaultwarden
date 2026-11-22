import UIKit
import XCTest

@MainActor
final class SyncRecoveryTests: XCTestCase {
    func testQueueShowsUnresolvedWorkAndRequiresExplicitRecovery() {
        continueAfterFailure = false
        XCUIDevice.shared.orientation = UIDevice.current.userInterfaceIdiom == .pad ? .landscapeLeft : .portrait
        let app = XCUIApplication()
        app.launchArguments = ["--fixture-sync-issues"]
        app.launch()

        let warning = app.buttons["sync.attention"].firstMatch
        XCTAssertTrue(warning.wait(for: \.isHittable, toEqual: true, timeout: 8))
        warning.tap()

        let status = app.staticTexts["sync.status"]
        XCTAssertTrue(status.waitForExistence(timeout: 5))
        XCTAssertFalse(status.label.hasPrefix("已同步"))
        attachScreenshot("Sync-issues")
        let update = app.buttons["sync.issue.1"]
        let unconfirmed = app.buttons["sync.issue.2"]
        reveal(unconfirmed, in: app)
        XCTAssertTrue(unconfirmed.label.contains("Fixture unconfirmed item"))
        unconfirmed.tap()
        let duplicateWarning = app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "可能产生重复条目")).firstMatch
        XCTAssertTrue(duplicateWarning.waitForExistence(timeout: 5))
        attachScreenshot("Sync-unconfirmed-create")
        let discard = app.buttons["放弃本机条目"].firstMatch
        XCTAssertTrue(discard.isEnabled)
        discard.tap()
        XCTAssertTrue(unconfirmed.waitForNonExistence(timeout: 5))

        reveal(update, in: app)
        XCTAssertTrue(update.label.contains("Fixture local edit"))
        update.tap()
        let server = app.buttons["采用服务器状态"].firstMatch
        XCTAssertTrue(server.waitForExistence(timeout: 5))
        let cancel = app.buttons["取消"].firstMatch
        if cancel.exists { cancel.tap() }
        else { app.otherElements["PopoverDismissRegion"].tap() }
        XCTAssertTrue(server.waitForNonExistence(timeout: 5))
        XCTAssertTrue(update.wait(for: \.isHittable, toEqual: true, timeout: 5))

        update.tap()
        let keep = app.buttons["保留本机副本"].firstMatch
        XCTAssertTrue(keep.waitForExistence(timeout: 5))
        keep.tap()
        XCTAssertTrue(update.waitForNonExistence(timeout: 5))
        XCTAssertTrue(app.descendants(matching: .any)["sync.queue.pending"].firstMatch.waitForExistence(timeout: 5))
        XCTAssertTrue(app.descendants(matching: .any)["sync.queue.receipt"].firstMatch.waitForExistence(timeout: 5))
        XCTAssertFalse(status.label.hasPrefix("已同步"))
        XCTAssertTrue(app.buttons["立即同步"].isEnabled)
        attachScreenshot("Sync-pending-copy")
    }

    private func attachScreenshot(_ name: String) {
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    private func reveal(_ element: XCUIElement, in app: XCUIApplication, line: UInt = #line) {
        for _ in 0..<3 where !element.isHittable { app.swipeUp() }
        XCTAssertTrue(element.wait(for: \.isHittable, toEqual: true, timeout: 5), element.debugDescription, line: line)
    }
}
