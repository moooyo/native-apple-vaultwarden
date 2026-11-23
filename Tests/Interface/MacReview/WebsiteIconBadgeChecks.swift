import AppKit
import CoreGraphics
import ImageIO
import Networking
import SwiftUI
import VaultModels
import VaultRepository

extension ReviewBoards {
    func checkWebsiteIconBadge() async throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString, directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let renderer = WindowRenderer(directory: directory, dark: false)
        let website = "https://example.com/sign-in"
        guard let server = ServerEnvironment(string: "https://fixture.example.invalid"),
              let location = WebsiteIconLocation(server: server, websites: [website]),
              let context = badgeBitmap(width: 32, height: 32) else {
            throw CheckFailure(message: "Create the isolated website icon fixture")
        }
        context.setFillColor(red: 1, green: 0, blue: 1, alpha: 1)
        context.fill(CGRect(x: 0, y: 0, width: 32, height: 32))
        guard let image = context.makeImage() else { throw CheckFailure(message: "Create a synthetic icon") }

        let cipher = PlaintextCipher(type: CipherType.login.rawValue, name: "GitLab review fixture",
                                     login: .init(uris: [.init(uri: website)]))
        let fixture = ReviewWebsiteIconFixture()
        let icons = MacWebsiteIcons(server: server, sessionIsCurrent: { true }) { requested in
            await fixture.pause(requested)
            return image
        }
        defer { icons.invalidate(); fixture.release() }
        let diameter: CGFloat = 30
        let size = CGSize(width: diameter, height: diameter)
        try await renderer.inspect(width: 160, height: 120) {
            MacVaultItemBadge(cipher, diameter: diameter)
                .onGeometryChange(for: CGSize.self, of: \.size) { fixture.size = $0 }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(.white)
                .environment(\.macWebsiteIcons, icons)
        } perform: { window in
            try await waitFor("the mounted badge asks for its website icon") { fixture.requested == location }
            try await checkBadgeFrame(showingIcon: false, window: window, renderer: renderer)
            try require(fixture.size == size, "the built-in badge fits 30 × 30 points")

            fixture.release()
            try await checkBadgeFrame(showingIcon: true, window: window, renderer: renderer)
            try require(fixture.size == size, "the synthetic icon fits the same 30 × 30 points")

            icons.invalidate()
            try await checkBadgeFrame(showingIcon: false, window: window, renderer: renderer)
            try require(fixture.size == size, "the restored built-in badge still fits 30 × 30 points")
        }
        print("Website icon badge: the built-in badge, synthetic icon, and restored built-in badge share a 30 × 30-point frame.")
    }

    private func checkBadgeFrame(showingIcon: Bool, window: NSWindow, renderer: WindowRenderer) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        let name = "Website-Icon-Badge"
        let file = renderer.directory.appending(path: name + ".png")
        repeat {
            try renderer.captureContent(window, board: name)
            guard let source = CGImageSourceCreateWithURL(file as CFURL, nil),
                  let image = CGImageSourceCreateImageAtIndex(source, 0, nil),
                  let colors = badgeBitmap(width: image.width, height: image.height),
                  let pixels = colors.data?.assumingMemoryBound(to: UInt8.self) else {
                throw CheckFailure(message: "Read the offscreen badge frame")
            }
            colors.draw(image, in: CGRect(x: 0, y: 0, width: image.width, height: image.height))
            var magenta = 0
            var orange = 0
            for offset in stride(from: 0, to: image.width * image.height * 4, by: 4) {
                let red = Int(pixels[offset])
                let green = Int(pixels[offset + 1])
                let blue = Int(pixels[offset + 2])
                if red > 160 && green < 100 && blue > 160 { magenta += 1 }
                if red > 130 && red - green > 65 && blue < 100 { orange += 1 }
            }
            withExtendedLifetime(colors) {}
            if showingIcon ? magenta > 100 && orange == 0 : orange > 100 && magenta == 0 { return }
            try await Task.sleep(for: .milliseconds(80))
        } while ContinuousClock.now < deadline
        throw CheckFailure(message: showingIcon ? "The badge did not render the synthetic icon" : "The badge did not render its built-in GitLab badge")
    }
}

private func badgeBitmap(width: Int, height: Int) -> CGContext? {
    guard let colorSpace = CGColorSpace(name: CGColorSpace.sRGB) else { return nil }
    return CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: width * 4,
                     space: colorSpace, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue | CGBitmapInfo.byteOrder32Big.rawValue)
}

@MainActor private final class ReviewWebsiteIconFixture {
    private(set) var requested: WebsiteIconLocation?
    private var paused: CheckedContinuation<Void, Never>?
    private var released = false
    var size: CGSize?

    func pause(_ location: WebsiteIconLocation) async {
        guard requested == nil else { return }
        requested = location
        guard !released else { return }
        await withCheckedContinuation { paused = $0 }
    }

    func release() {
        released = true
        paused?.resume()
        paused = nil
    }
}
