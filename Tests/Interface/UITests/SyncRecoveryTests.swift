import UIKit
import XCTest

@MainActor
final class SyncRecoveryTests: XCTestCase {
    func testQueueShowsUnresolvedWorkAndRequiresExplicitRecovery() {
        checkQueue(padSidebarExpanded: true)
    }

    func testQueueRecoveryWithCollapsedPadSidebar() throws {
        try XCTSkipUnless(UIDevice.current.userInterfaceIdiom == .pad, "Requires the iPad sidebar.")
        checkQueue(padSidebarExpanded: false)
    }

    private func checkQueue(padSidebarExpanded: Bool) {
        continueAfterFailure = false
        let isPad = UIDevice.current.userInterfaceIdiom == .pad
        XCUIDevice.shared.orientation = isPad ? .landscapeLeft : .portrait
        let app = XCUIApplication()
        app.launchArguments = ["--fixture-sync-issues"]
        app.launch()
        if isPad { setPadSidebar(expanded: padSidebarExpanded, in: app) }

        let warning = app.buttons["sync.attention"].firstMatch
        XCTAssertTrue(warning.wait(for: \.isHittable, toEqual: true, timeout: 8))
        warning.tap()

        let status = app.staticTexts["sync.status"]
        XCTAssertTrue(status.waitForExistence(timeout: 5))
        XCTAssertFalse(status.label.hasPrefix("已同步"))
        let list = app.collectionViews.containing(.staticText, identifier: "sync.status").firstMatch
        XCTAssertTrue(list.exists, "Expected the account settings list.")
        let screenshotSuffix = isPad && !padSidebarExpanded ? "-Collapsed-Pad" : ""
        attachScreenshot("Sync-issues\(screenshotSuffix)")
        let update = app.buttons["sync.issue.1"]
        let unconfirmed = app.buttons["sync.issue.2"]
        tapQueueRow(unconfirmed, named: "Fixture unconfirmed item", in: list, app: app)
        let duplicateWarning = app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "可能产生重复条目")).firstMatch
        XCTAssertTrue(duplicateWarning.waitForExistence(timeout: 5))
        attachScreenshot("Sync-unconfirmed-create\(screenshotSuffix)")
        let discard = app.buttons["放弃本机条目"].firstMatch
        XCTAssertTrue(discard.isEnabled)
        discard.tap()
        XCTAssertTrue(unconfirmed.waitForNonExistence(timeout: 5))

        tapQueueRow(update, named: "Fixture local edit", in: list, app: app)
        let server = app.buttons["采用服务器状态"].firstMatch
        XCTAssertTrue(server.waitForExistence(timeout: 5))
        let cancel = app.buttons["取消"].firstMatch
        if cancel.exists { cancel.tap() }
        else { app.otherElements["PopoverDismissRegion"].tap() }
        XCTAssertTrue(server.waitForNonExistence(timeout: 5))
        XCTAssertTrue(update.exists, "Cancelling leaves the conflict unresolved.")

        tapQueueRow(update, named: "Fixture local edit", in: list, app: app)
        let keep = app.buttons["保留本机副本"].firstMatch
        XCTAssertTrue(keep.waitForExistence(timeout: 5))
        keep.tap()
        XCTAssertTrue(update.waitForNonExistence(timeout: 5))
        XCTAssertTrue(app.descendants(matching: .any)["sync.queue.pending"].firstMatch.waitForExistence(timeout: 5))
        XCTAssertTrue(app.descendants(matching: .any)["sync.queue.receipt"].firstMatch.waitForExistence(timeout: 5))
        XCTAssertFalse(status.label.hasPrefix("已同步"))
        XCTAssertTrue(app.buttons["立即同步"].isEnabled)
        attachScreenshot("Sync-pending-copy\(screenshotSuffix)")
    }

    private func setPadSidebar(expanded: Bool, in app: XCUIApplication) {
        let toggle = app.buttons.matching(NSPredicate(format: "identifier ==[c] %@", "ToggleSidebar")).firstMatch
        XCTAssertTrue(toggle.wait(for: \.isHittable, toEqual: true, timeout: 7))
        let sidebarTab = app.cells["tab.codes"]
        if sidebarTab.exists != expanded { toggle.tap() }
        if expanded {
            XCTAssertTrue(sidebarTab.wait(for: \.isHittable, toEqual: true, timeout: 5))
        } else {
            XCTAssertTrue(sidebarTab.waitForNonExistence(timeout: 5))
            XCTAssertTrue(app.buttons.matching(identifier: "tab.codes").firstMatch.waitForExistence(timeout: 5))
        }
    }

    private func tapQueueRow(_ row: XCUIElement, named name: String, in list: XCUIElement,
                             app: XCUIApplication, line: UInt = #line) {
        for _ in 0..<3 {
            let viewport = list.frame.intersection(app.frame)
            if row.exists, row.isHittable || viewport.contains(row.frame) { break }
            if row.exists, row.frame.midY < viewport.minY { list.swipeDown() }
            else { list.swipeUp() }
        }
        XCTAssertTrue(row.waitForExistence(timeout: 5), "Expected queue row \(name).", line: line)
        XCTAssertTrue(row.label.contains(name), line: line)
        XCTAssertTrue(row.wait(for: \.isEnabled, toEqual: true, timeout: 5), "Queue row is disabled: \(name).", line: line)
        if UIDevice.current.userInterfaceIdiom != .pad || row.isHittable {
            XCTAssertTrue(row.wait(for: \.isHittable, toEqual: true, timeout: 5), row.debugDescription, line: line)
            row.tap()
            return
        }

        // In the collapsed iPad layout, XCTest can report a visible, enabled List button as unhittable.
        let window = app.frame
        let frame = row.frame
        XCTAssertTrue(!frame.isEmpty && list.frame.intersection(window).contains(frame),
                      "Queue row is outside the visible account settings list: \(name).", line: line)
        app.coordinate(withNormalizedOffset: .zero)
            .withOffset(CGVector(dx: frame.midX - window.minX, dy: frame.midY - window.minY)).tap()
    }

    private func attachScreenshot(_ name: String) {
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
