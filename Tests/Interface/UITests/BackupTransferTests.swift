import UIKit
import XCTest

@MainActor
final class BackupTransferTests: XCTestCase {
    func testNativeFilesExportAndRestore() throws {
        continueAfterFailure = false
        let isPad = UIDevice.current.userInterfaceIdiom == .pad
        XCUIDevice.shared.orientation = isPad ? .landscapeLeft : .portrait
        let app = XCUIApplication()
        app.launchArguments = ["--fixture-backup"]
        app.launch()
        tap(app.segmentedControls.buttons["导出"])
        let password = app.secureTextFields.firstMatch
        tap(password)
        password.typeText("test-password")
        let export = app.buttons["导出…"]
        if !export.isHittable { app.swipeUp() }
        tap(export)

        let filename = isPad ? "Backup-\(UUID().uuidString.prefix(8))" : "OpenVault"
        try openFixtureDocuments(in: app, isPad: isPad)
        let name = app.textFields["DOCPicker.filenameTextField"]
        let save = app.buttons["DOCPicker.actionButton"]
        if isPad {
            touchCenter(of: name, in: app)
            name.typeText(filename)
            if (name.value as? String)?.contains("OpenVault") == true {
                name.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: "OpenVault".count + filename.count) + filename)
            }
            XCTAssertTrue((name.value as? String)?.contains(filename) == true)
        }
        touchCenter(of: save, in: app)
        XCTAssertTrue(app.staticTexts["保险库已导出。"].waitForExistence(timeout: 8), app.debugDescription)

        tap(app.segmentedControls.buttons["导入"])
        tap(app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "来源")).firstMatch)
        tap(app.buttons["Bitwarden（JSON）"].firstMatch)
        tap(app.buttons["选择文件并导入…"])
        let file = namedFile(filename, in: app)
        if !file.waitForExistence(timeout: 2) {
            try openFixtureDocuments(in: app, isPad: isPad)
            if !file.exists {
                let recentLabels = ["最近项目", "Recents"]
                let recents = isPad ? app.cells.matching(NSPredicate(format: "identifier BEGINSWITH %@ AND label IN %@",
                                                                    "DOC.sidebar.item.", recentLabels)).firstMatch
                    : app.buttons.matching(NSPredicate(format: "label IN %@", recentLabels)).firstMatch
                if recents.exists { touchCenter(of: recents, in: app) }
            }
        }
        XCTAssertTrue(file.waitForExistence(timeout: 10), app.debugDescription)
        touchCenter(of: file, in: app)
        XCTAssertTrue(app.staticTexts["已导入 9 个条目。"].waitForExistence(timeout: 8), app.debugDescription)
    }

    private func openFixtureDocuments(in app: XCUIApplication, isPad: Bool) throws {
        let location = app.cells.matching(NSPredicate(format: "identifier BEGINSWITH %@ AND (label CONTAINS[c] %@)",
                                                       "DOC.sidebar.item.", isPad ? "iPad" : "iPhone")).firstMatch
        let title = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "OpenVault Fixture, ")).firstMatch
        let folder = app.cells.matching(NSPredicate(format: "label BEGINSWITH %@ OR identifier BEGINSWITH %@",
                                                     "OpenVault Fixture", "OpenVault Fixture")).firstMatch
        let documentBrowser = app.otherElements.matching(NSPredicate(format: "identifier BEGINSWITH %@", "DOC.browsingRoot Source: com.apple.FileProvider.LocalStorage")).firstMatch
        let picker = app.otherElements["Browse View (Picker)"].firstMatch
        XCTAssertTrue(picker.waitForExistence(timeout: 20), app.debugDescription)
        if title.exists { return }
        if !folder.exists && !documentBrowser.exists {
            let browse = localizedButton(in: app, labels: ["浏览", "Browse"])
            for _ in 0..<2 where !location.exists && browse.exists { touchCenter(of: browse, in: app) }
            guard location.waitForExistence(timeout: 5) else {
                XCTFail("Could not open local Files locations: \(app.debugDescription)")
                return
            }
            touchCenter(of: location, in: app)
        }
        if title.exists { return }
        XCTAssertTrue(folder.waitForExistence(timeout: 5), app.debugDescription)
        touchCenter(of: folder, in: app)
    }

    private func namedFile(_ basename: String, in app: XCUIApplication) -> XCUIElement {
        app.cells.matching(NSPredicate(format: "label BEGINSWITH %@ OR identifier BEGINSWITH %@", basename, basename)).firstMatch
    }

    private func localizedButton(in app: XCUIApplication, labels: [String]) -> XCUIElement {
        app.buttons.matching(NSPredicate(format: "label IN %@", labels)).firstMatch
    }

    private func tap(_ element: XCUIElement, line: UInt = #line) {
        XCTAssertTrue(element.wait(for: \.isHittable, toEqual: true, timeout: 5), "Cannot tap \(element)", line: line)
        element.tap()
    }

    private func touchCenter(of element: XCUIElement, in app: XCUIApplication, line: UInt = #line) {
        XCTAssertTrue(element.waitForExistence(timeout: 5), app.debugDescription, line: line)
        let frame = app.frame
        let point = CGPoint(x: element.frame.midX, y: element.frame.midY)
        XCTAssertTrue(frame.contains(point), "File element is outside the app frame: \(element)", line: line)
        app.coordinate(withNormalizedOffset: .zero)
            .withOffset(CGVector(dx: point.x - frame.minX, dy: point.y - frame.minY)).tap()
    }
}
