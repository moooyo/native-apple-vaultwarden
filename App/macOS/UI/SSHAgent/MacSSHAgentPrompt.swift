import AppKit
import SwiftUI

@MainActor
final class MacSSHAgentPrompt: NSObject, NSWindowDelegate {
    private struct Pending {
        let id: UUID
        let panel: NSPanel
        let result: CheckedContinuation<Bool, Never>
        let timeout: Task<Void, Never>
    }

    private var pending: Pending?
    private let present: (NSPanel) -> Void

    init(present: @escaping (NSPanel) -> Void = { panel in
        NSApplication.shared.activate()
        panel.makeKeyAndOrderFront(nil)
    }) {
        self.present = present
    }

    func request(_ approval: MacSSHAgentApproval) async -> Bool {
        guard pending == nil, !Task.isCancelled else { return false }
        let id = UUID()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                guard !Task.isCancelled else {
                    continuation.resume(returning: false)
                    return
                }
                let panel = NSPanel(contentRect: CGRect(origin: .zero, size: CGSize(width: 440, height: 248)),
                                    styleMask: [.titled, .closable], backing: .buffered, defer: false)
                panel.title = MacLocalization.text("OpenVault SSH Request", table: "MacSSHAgent")
                panel.contentView = NSHostingView(rootView: ApprovalView(approval: approval) { [weak self] allowed in
                    self?.finish(id, allowed: allowed)
                }.macInterfaceLanguage())
                panel.isReleasedWhenClosed = false
                panel.delegate = self
                panel.level = .modalPanel
                panel.hidesOnDeactivate = false
                panel.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
                panel.isExcludedFromWindowsMenu = true
                panel.isRestorable = false
                panel.center()
                let timeout = Task { [weak self] in
                    do { try await Task.sleep(for: .seconds(30)) } catch { return }
                    self?.finish(id, allowed: false)
                }
                pending = Pending(id: id, panel: panel, result: continuation, timeout: timeout)
                present(panel)
            }
        } onCancel: { [weak self] in
            Task { @MainActor in self?.finish(id, allowed: false) }
        }
    }

    func windowWillClose(_ notification: Notification) {
        guard let pending, notification.object as? NSWindow === pending.panel else { return }
        finish(pending.id, allowed: false)
    }

    private func finish(_ id: UUID, allowed: Bool) {
        guard let pending, pending.id == id else { return }
        self.pending = nil
        pending.timeout.cancel()
        pending.panel.orderOut(nil)
        pending.result.resume(returning: allowed)
    }

    private struct ApprovalView: View {
        let approval: MacSSHAgentApproval
        let decide: (Bool) -> Void

        var body: some View {
            VStack(alignment: .leading, spacing: 14) {
                Label { Text("Authorize an SSH signature?", tableName: "MacSSHAgent") } icon: { Image(systemName: "key.fill") }
                    .font(.title3.weight(.semibold))
                VStack(alignment: .leading, spacing: 8) {
                    LabeledContent {
                        Text(verbatim: approval.keyName).lineLimit(2).privacySensitive()
                    } label: { Text("Vault Item", tableName: "MacSSHAgent") }
                    LabeledContent {
                        if let name = approval.peer.name, let pid = approval.peer.pid {
                            Text(verbatim: "\(name) (\(pid))").lineLimit(1).truncationMode(.tail)
                        } else {
                            Text("Unknown local process", tableName: "MacSSHAgent")
                        }
                    } label: { Text("Local Caller", tableName: "MacSSHAgent") }
                }
                Text("Allow only if you started this request. OpenVault cannot verify the remote destination.", tableName: "MacSSHAgent")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 0)
                HStack {
                    Spacer()
                    Button { decide(false) } label: { Text("Deny", tableName: "MacSSHAgent") }
                        .keyboardShortcut(.cancelAction)
                    Button { decide(true) } label: { Text("Authorize", tableName: "MacSSHAgent") }
                        .accessibilityIdentifier("ssh-agent.authorize")
                }
            }
            .padding(24)
            .frame(width: 440, height: 248)
        }
    }
}
