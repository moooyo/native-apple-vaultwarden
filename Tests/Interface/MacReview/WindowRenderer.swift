import AppKit
import ScreenCaptureKit
import SwiftUI

@MainActor
struct WindowRenderer {
    let directory: URL
    let dark: Bool

    func inspect<Content: View>(width: CGFloat, height: CGFloat, title: String? = nil, toolbarStyle: NSWindow.ToolbarStyle = .automatic,
                                @ViewBuilder content: () -> Content,
                                perform checks: (NSWindow) async throws -> Void) async throws {
        let window = host(width: width, height: height, title: title, toolbarStyle: toolbarStyle) { content().environment(\.accessibilityEnabled, true) }
        defer { window.close() }
        try await settle(window)
        try await checks(window)
        try await settle(window)
    }

    func capture<Content: View>(_ board: String, width: CGFloat, height: CGFloat, title: String? = nil,
                                toolbarStyle: NSWindow.ToolbarStyle = .automatic, contentOnly: Bool = false,
                                @ViewBuilder content: () -> Content) async throws {
        let window = host(width: width, height: height, title: title, toolbarStyle: toolbarStyle, content: content)
        defer { window.close() }
        try await settle(window)
        if contentOnly { try captureContent(window, board: board) }
        else { try await captureWindow(window, board: board) }
    }

    func captureContent(_ window: NSWindow, board: String) throws {
        guard let content = window.contentView else { throw ReviewError.windowMissing }
        content.layoutSubtreeIfNeeded()
        content.displayIfNeeded()
        guard let image = content.bitmapImageRepForCachingDisplay(in: content.bounds) else { throw ReviewError.bitmap }
        content.cacheDisplay(in: content.bounds, to: image)
        try write(image, board: board)
    }

    func captureSheet<Parent: View, Sheet: View>(_ board: String, width: CGFloat, height: CGFloat,
                                                 @ViewBuilder parent: () -> Parent, @ViewBuilder sheet: () -> Sheet) async throws {
        let window = host(width: width, height: height, title: "OpenVault", content: parent)
        let panel = host(width: width, height: height, title: nil, content: sheet)
        defer { panel.close(); window.close() }
        try await settle(panel)
        guard let fittingSize = panel.measureContent?(window.contentLayoutRect.size),
              fittingSize.width.isFinite, fittingSize.height.isFinite, fittingSize.width > 0, fittingSize.height > 0 else {
            throw ReviewError.sheetSize
        }
        panel.setContentSize(fittingSize)
        window.beginSheet(panel, completionHandler: nil)
        defer { window.endSheet(panel) }
        try await settle(window)
        try await settle(panel)
        try await captureWindow(window, board: board, sheet: panel)
    }

    private func host<Content: View>(width: CGFloat, height: CGFloat, title: String?,
                                     toolbarStyle: NSWindow.ToolbarStyle = .automatic, @ViewBuilder content: () -> Content) -> ReviewWindow {
        var style: NSWindow.StyleMask = title == nil ? [.borderless] : [.titled, .closable, .miniaturizable, .resizable]
        if title != nil && toolbarStyle == .automatic { style.insert(.fullSizeContentView) }
        let display = NSScreen.main?.frame ?? .zero
        let frame = NSRect(x: display.midX - width / 2, y: display.midY - height / 2, width: width, height: height)
        let window = ReviewWindow(contentRect: frame, styleMask: style, backing: .buffered, defer: false)
        window.level = ReviewWindow.belowDesktop
        window.ignoresMouseEvents = true
        window.isReleasedWhenClosed = false
        window.isRestorable = false
        window.hasShadow = false
        window.isExcludedFromWindowsMenu = true
        window.title = title ?? ""
        window.toolbarStyle = toolbarStyle
        window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
        let view = content().environment(\.locale, Locale(identifier: "zh_CN")).environment(\.colorScheme, dark ? .dark : .light)
            .environment(\.appearsActive, true)
        let controller = NSHostingController(rootView: view)
        controller.sizingOptions = []
        window.measureContent = { [weak controller] proposal in controller?.sizeThatFits(in: proposal) ?? .zero }
        window.contentViewController = controller
        if toolbarStyle == .expanded { window.toolbar?.displayMode = .iconAndLabel }
        window.setFrame(frame, display: false)
        window.orderBack(nil)
        return window
    }

    private func settle(_ window: NSWindow) async throws {
        window.contentView?.layoutSubtreeIfNeeded()
        window.displayIfNeeded()
        try await Task.sleep(for: .milliseconds(500))
        window.contentView?.layoutSubtreeIfNeeded()
        window.displayIfNeeded()
        guard window.level.rawValue <= ReviewWindow.belowDesktop.rawValue && !NSApp.isActive else { throw ReviewError.visibleWindow }
    }

    func captureWindow(_ window: NSWindow, board: String, sheet: NSWindow? = nil) async throws {
        let inventory = try await SCShareableContent.currentProcess
        func ownImage(_ window: NSWindow) async throws -> CGImage {
            guard let ownWindow = inventory.windows.first(where: { $0.windowID == window.windowNumber
                && $0.owningApplication?.processID == ProcessInfo.processInfo.processIdentifier }) else { throw ReviewError.windowMissing }
            let filter = SCContentFilter(desktopIndependentWindow: ownWindow)
            let configuration = SCStreamConfiguration()
            configuration.width = Int(window.frame.width)
            configuration.height = Int(window.frame.height)
            configuration.showsCursor = false
            configuration.ignoreShadowsSingleWindow = true
            configuration.ignoreGlobalClipSingleWindow = true
            configuration.includeChildWindows = false
            return try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: configuration)
        }
        let base = try await ownImage(window)
        guard let sheet else { try write(NSBitmapImageRep(cgImage: base), board: board); return }
        let overlay = try await ownImage(sheet)
        guard let space = CGColorSpace(name: CGColorSpace.sRGB),
              let context = CGContext(data: nil, width: base.width, height: base.height, bitsPerComponent: 8, bytesPerRow: 0,
                                      space: space, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
        else { throw ReviewError.bitmap }
        context.draw(base, in: CGRect(origin: .zero, size: window.frame.size))
        context.draw(overlay, in: sheet.frame.offsetBy(dx: -window.frame.minX, dy: -window.frame.minY))
        guard let result = context.makeImage() else { throw ReviewError.bitmap }
        try write(NSBitmapImageRep(cgImage: result), board: board)
    }

    private func write(_ image: NSBitmapImageRep, board: String) throws {
        guard let png = image.representation(using: .png, properties: [:]) else { throw ReviewError.bitmap }
        let url = directory.appending(path: board + ".png")
        try png.write(to: url, options: .atomic)
        print("\(board): \(image.pixelsWide) × \(image.pixelsHigh)")
    }
}

private final class ReviewWindow: NSWindow {
    var measureContent: ((CGSize) -> CGSize)?
    static let belowDesktop = NSWindow.Level(rawValue: Int(CGWindowLevelForKey(.desktopWindow)) - 1)
    override var canBecomeKey: Bool { false }
    override var canBecomeMain: Bool { false }
    override var level: NSWindow.Level {
        get { super.level }
        set { super.level = NSWindow.Level(rawValue: min(newValue.rawValue, Self.belowDesktop.rawValue)) }
    }
}

enum ReviewError: Error { case bitmap, visibleWindow, windowMissing, sheetSize }
