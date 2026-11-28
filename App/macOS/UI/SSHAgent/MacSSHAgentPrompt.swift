import AppKit
import CoreGraphics
import Observation
import SwiftUI

@MainActor @Observable
final class MacSSHApprovalPanelModel {
    enum Phase: Equatable { case ask, touch, password, done(MacSSHApprovalDuration), denied }
    enum Factor { case touchID, password(String) }
    enum Verification { case verified, cancelled, passwordRequired, passwordRejected }
    typealias Authenticate = @MainActor (MacSSHAgentApproval, Factor) async -> Verification

    let approval: MacSSHAgentApproval
    let allowedDurations: [MacSSHApprovalDuration]
    private(set) var phase: Phase = .ask
    var duration: MacSSHApprovalDuration
    var password = "" { didSet { if !password.isEmpty { passwordRejected = false } } }
    private(set) var passwordRejected = false
    private(set) var isCheckingPassword = false
    private(set) var isAuthorized = false

    @ObservationIgnored private let authenticate: Authenticate
    @ObservationIgnored private let decide: (MacSSHApprovalDuration?) -> Void
    @ObservationIgnored private let now: () -> ContinuousClock.Instant
    @ObservationIgnored private let announce: (String) -> Void
    @ObservationIgnored private var start: ContinuousClock.Instant?
    @ObservationIgnored private var countdownTask: Task<Void, Never>?
    @ObservationIgnored private var attempt: (id: UUID, task: Task<Void, Never>)?

    init(approval: MacSSHAgentApproval, authenticate: @escaping Authenticate, decide: @escaping (MacSSHApprovalDuration?) -> Void,
         now: @escaping () -> ContinuousClock.Instant = { .now }, announce: @escaping (String) -> Void = {
             AccessibilityNotification.Announcement($0).post()
         }) {
        self.approval = approval
        self.authenticate = authenticate
        self.decide = decide
        self.now = now
        self.announce = announce
        allowedDurations = approval.peer.signingIdentity == nil ? [.once] : MacSSHApprovalDuration.allCases
        duration = allowedDurations.contains(approval.defaultDuration) ? approval.defaultDuration : .once
    }

    func startCountdown() {
        phase = .ask
        let origin = now()
        start = origin
        countdownTask?.cancel()
        countdownTask = Task { [weak self] in
            do {
                for mark in [30, 10, 5] {
                    if mark != 30 { try await ContinuousClock().sleep(until: origin.advanced(by: .seconds(30 - mark))) }
                    guard let self, !Task.isCancelled else { return }
                    announce(macSSHAgentText("Deny, automatically denied in %lld seconds", mark))
                }
                try await ContinuousClock().sleep(until: origin.advanced(by: MacSSHApprovalCountdown.duration))
                self?.deny()
            } catch { return }
        }
    }

    func countdown(reduceMotion: Bool) -> MacSSHApprovalCountdown {
        MacSSHApprovalCountdown(elapsed: start?.duration(to: now()) ?? .zero, reduceMotion: reduceMotion)
    }

    func approve() {
        guard phase == .ask else { return }
        guard countdown(reduceMotion: false).seconds > 0 else { deny(); return }
        stopCountdown()
        phase = .touch
        verify(.touchID)
    }

    func deny() {
        guard phase == .ask else { return }
        decide(nil)
    }

    func usePassword() {
        guard phase == .touch, !isAuthorized else { return }
        clearVerification()
        phase = .password
    }

    func submitPassword() {
        guard phase == .password, !password.isEmpty, !isCheckingPassword, !isAuthorized else { return }
        let input = password
        password = ""
        passwordRejected = false
        isCheckingPassword = true
        verify(.password(input))
    }

    func cancelVerification() {
        guard (phase == .touch || phase == .password), !isAuthorized else { return }
        clearVerification()
        startCountdown()
    }

    func showReceipt(approved: Bool) {
        stopCountdown()
        clearVerification()
        phase = approved ? .done(duration) : .denied
    }

    private func verify(_ factor: Factor) {
        let id = UUID()
        let task = Task { [weak self, authenticate, approval] in
            let result = await authenticate(approval, factor)
            guard let self, !Task.isCancelled, attempt?.id == id else { return }
            attempt = nil
            isCheckingPassword = false
            switch result {
            case .verified:
                isAuthorized = true
                isCheckingPassword = phase == .password
                if !allowedDurations.contains(duration) { duration = .once }
                decide(duration)
            case .cancelled: cancelVerification()
            case .passwordRequired: usePassword()
            case .passwordRejected:
                passwordRejected = true
                announce(macSSHAgentText("Password verification failed"))
            }
        }
        attempt = (id, task)
    }

    private func stopCountdown() {
        countdownTask?.cancel()
        countdownTask = nil
        start = nil
    }

    private func clearVerification() {
        attempt?.task.cancel()
        attempt = nil
        password = ""
        isCheckingPassword = false
        passwordRejected = false
    }
}

@MainActor
final class MacSSHAgentPrompt: NSObject, NSWindowDelegate {
    private struct Pending {
        let panel: MacSSHApprovalPanel
        let model: MacSSHApprovalPanelModel
        var result: CheckedContinuation<MacSSHApprovalDuration?, Never>?
        var dismissal: Task<Void, Never>?
    }

    private var pending: Pending?
    private var generation: UInt64 = 0
    private let present: (NSPanel) -> Void
    private let authenticate: MacSSHApprovalPanelModel.Authenticate
    private let receiptTime: Duration

    init(authenticate: @escaping MacSSHApprovalPanelModel.Authenticate, receiptTime: Duration = .milliseconds(1200),
         present: @escaping (NSPanel) -> Void = { $0.orderFrontRegardless() }) {
        self.authenticate = authenticate
        self.receiptTime = receiptTime
        self.present = present
    }

    func request(_ approval: MacSSHAgentApproval) async -> MacSSHApprovalDuration? {
        let generation = self.generation
        if let dismissal = pending?.dismissal { await dismissal.value }
        guard generation == self.generation, pending == nil, !Task.isCancelled else { return nil }
        let id = approval.id
        return await withTaskCancellationHandler {
            await withCheckedContinuation { result in
                guard !Task.isCancelled else { result.resume(returning: nil); return }
                let model = MacSSHApprovalPanelModel(approval: approval, authenticate: authenticate) { [weak self] decision in
                    self?.decide(id, duration: decision)
                }
                let panel = MacSSHApprovalPanel(model: model)
                panel.delegate = self
                pending = Pending(panel: panel, model: model, result: result)
                present(panel)
                model.startCountdown()
            }
        } onCancel: { [weak self] in
            Task { @MainActor in self?.complete(id, approved: false) }
        }
    }

    func complete(_ id: UUID, approved: Bool) {
        guard let current = pending, current.model.approval.id == id, current.dismissal == nil else { return }
        pending?.result = nil
        current.model.showReceipt(approved: approved && current.model.isAuthorized)
        pending?.dismissal = Task { [weak self, receiptTime] in
            do { try await Task.sleep(for: receiptTime) } catch { return }
            self?.dismiss(id)
        }
        current.result?.resume(returning: nil)
    }

    func reject() {
        generation &+= 1
        guard let id = pending?.model.approval.id else { return }
        complete(id, approved: false)
    }

    func windowWillClose(_ notification: Notification) {
        guard let current = pending, notification.object as? NSWindow === current.panel else { return }
        let id = current.model.approval.id
        complete(id, approved: false)
        dismiss(id)
    }

    private func decide(_ id: UUID, duration: MacSSHApprovalDuration?) {
        guard let current = pending, current.model.approval.id == id, let result = current.result else { return }
        if let duration {
            pending?.result = nil
            result.resume(returning: duration)
        } else {
            complete(id, approved: false)
        }
    }

    private func dismiss(_ id: UUID) {
        guard let current = pending, current.model.approval.id == id else { return }
        pending = nil
        current.dismissal?.cancel()
        current.panel.orderOut(nil)
    }
}

@MainActor
final class MacSSHApprovalPanel: NSPanel {
    let model: MacSSHApprovalPanelModel

    init(model: MacSSHApprovalPanelModel) {
        self.model = model
        super.init(contentRect: CGRect(origin: .zero, size: MacSSHApprovalPanelView.size),
                   styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        backgroundColor = .clear
        isOpaque = false
        hasShadow = true
        isFloatingPanel = true
        level = .floating
        hidesOnDeactivate = false
        isReleasedWhenClosed = false
        isExcludedFromWindowsMenu = true
        isRestorable = false
        collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary, .ignoresCycle]
        contentView = NSHostingView(rootView: MacSSHApprovalPanelView(model: model).macInterfaceLanguage())
        if let screen = Self.requestScreen() {
            setFrameOrigin(Self.position(for: frame.size, in: screen.visibleFrame))
        }
    }

    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }

    override func sendEvent(_ event: NSEvent) {
        if isKeyWindow, event.type == .keyDown,
           event.modifierFlags.intersection([.command, .option, .control, .shift]).isEmpty {
            switch (event.keyCode, model.phase) {
            case (53, .ask): model.deny(); return
            case (53, .touch), (53, .password): model.cancelVerification(); return
            case (36, .ask), (76, .ask): model.approve(); return
            default: break
            }
        }
        super.sendEvent(event)
    }

    static func position(for size: CGSize, in bounds: CGRect) -> CGPoint {
        CGPoint(x: bounds.midX - size.width / 2,
                y: max(bounds.minY, min(bounds.maxY - size.height, bounds.maxY - bounds.height / 3 - size.height / 2)))
    }

    private static func requestScreen() -> NSScreen? {
        let screens = NSScreen.screens
        if let pid = NSWorkspace.shared.frontmostApplication?.processIdentifier,
           let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] {
            for window in windows where window[kCGWindowOwnerPID as String] as? pid_t == pid
                && window[kCGWindowLayer as String] as? Int == 0 {
                guard let dictionary = window[kCGWindowBounds as String] as? NSDictionary,
                      let bounds = CGRect(dictionaryRepresentation: dictionary as CFDictionary),
                      bounds.width > 0, bounds.height > 0 else { continue }
                let intersections = screens.compactMap { screen -> (NSScreen, CGFloat)? in
                    guard let number = screen.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber else { return nil }
                    let overlap = CGDisplayBounds(number.uint32Value).intersection(bounds)
                    guard !overlap.isNull, !overlap.isEmpty else { return nil }
                    return (screen, overlap.width * overlap.height)
                }
                if let screen = intersections.max(by: { $0.1 < $1.1 })?.0 { return screen }
            }
        }
        return screens.first(where: { $0.frame.contains(NSEvent.mouseLocation) }) ?? NSScreen.main
    }
}
