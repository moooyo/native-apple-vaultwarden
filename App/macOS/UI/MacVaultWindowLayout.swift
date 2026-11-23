import AppKit
import SwiftUI

enum MacWindowSize {
    static let vaultDefault = CGSize(width: 1280, height: 800)
    static let vaultMinimum = CGSize(width: 850, height: 560)
    static let credentialsFrame = CGSize(width: 560, height: 500)
    @MainActor static let credentialsContent = NSWindow.contentRect(
        forFrameRect: CGRect(origin: .zero, size: credentialsFrame),
        styleMask: [.titled, .closable, .miniaturizable]
    ).size
}

struct MacVaultWindowLayout: ViewModifier {
    let locked: Bool
    @SceneStorage("openvault.workspace.windowFrame") private var workspaceFrame: String?
    @State private var fullScreen = false

    func body(content: Content) -> some View {
        let minimum = locked ? MacWindowSize.credentialsContent : MacWindowSize.vaultMinimum
        content
            .frame(minWidth: minimum.width, minHeight: minimum.height)
            .background {
                MacVaultWindowFrame(locked: locked, workspaceFrame: $workspaceFrame, fullScreen: $fullScreen)
            }
            .windowResizeBehavior(locked && !fullScreen ? .disabled : .automatic)
            .windowFullScreenBehavior(locked && !fullScreen ? .disabled : .automatic)
    }
}

private struct MacVaultWindowFrame: NSViewRepresentable {
    let locked: Bool
    @Binding var workspaceFrame: String?
    @Binding var fullScreen: Bool

    func makeNSView(context: Context) -> FrameView { FrameView() }

    func updateNSView(_ view: FrameView, context: Context) {
        view.update(locked: locked, workspaceFrame: $workspaceFrame, fullScreen: $fullScreen)
    }

    final class FrameView: NSView {
        private weak var observedWindow: NSWindow?
        private var locked = false
        private var appliedLocked: Bool?
        private var workspaceFrame: Binding<String?> = .constant(nil)
        private var fullScreen: Binding<Bool> = .constant(false)

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard observedWindow !== window else { return }
            let notifications = NotificationCenter.default
            notifications.removeObserver(self)
            observedWindow = window
            appliedLocked = nil
            if let window {
                for name in [NSWindow.didEnterFullScreenNotification, NSWindow.didExitFullScreenNotification] {
                    notifications.addObserver(self, selector: #selector(fullScreenChanged(_:)), name: name, object: window)
                }
                scheduleFrameUpdate()
            }
        }

        func update(locked: Bool, workspaceFrame: Binding<String?>, fullScreen: Binding<Bool>) {
            self.workspaceFrame = workspaceFrame
            self.fullScreen = fullScreen
            guard self.locked != locked else { return }
            self.locked = locked
            scheduleFrameUpdate()
        }

        @objc private func fullScreenChanged(_ notification: Notification) { scheduleFrameUpdate() }

        private func scheduleFrameUpdate() {
            DispatchQueue.main.async { [weak self] in self?.updateFrame() }
        }

        private func updateFrame() {
            guard let window else { return }
            let isFullScreen = window.styleMask.contains(.fullScreen)
            if fullScreen.wrappedValue != isFullScreen { fullScreen.wrappedValue = isFullScreen }
            guard !isFullScreen, appliedLocked != locked else { return }
            appliedLocked = locked
            if locked {
                let frame = window.frame
                if workspaceFrame.wrappedValue == nil {
                    let minimum = MacWindowSize.vaultMinimum
                    let content = window.contentRect(forFrameRect: frame).size
                    let defaultFrame = window.frameRect(forContentRect: CGRect(origin: .zero, size: MacWindowSize.vaultDefault))
                    let restoreFrame = content.width >= minimum.width && content.height >= minimum.height
                        ? frame : centered(defaultFrame.size, in: frame)
                    workspaceFrame.wrappedValue = NSStringFromRect(restoreFrame)
                }
                window.setFrame(centered(MacWindowSize.credentialsFrame, in: frame), display: window.isVisible)
            } else if let saved = workspaceFrame.wrappedValue {
                workspaceFrame.wrappedValue = nil
                window.setFrame(NSRectFromString(saved), display: window.isVisible)
            }
        }

        private func centered(_ size: CGSize, in frame: CGRect) -> CGRect {
            CGRect(x: (frame.midX - size.width / 2).rounded(), y: (frame.midY - size.height / 2).rounded(),
                   width: size.width, height: size.height)
        }
    }
}
