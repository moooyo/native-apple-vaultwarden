import Accessibility
import SwiftUI
import DesignSystem

@MainActor
@Observable
final class VaultOperationFeedback {
    struct Notice: Identifiable {
        let id = UUID()
        let message: String
        let expires = ContinuousClock.now.advanced(by: .seconds(4))
        let undo: (@MainActor () async throws -> Void)?
    }

    private(set) var notice: Notice?

    func show(_ message: String, undo: (@MainActor () async throws -> Void)? = nil) {
        notice = Notice(message: message, undo: undo)
        AccessibilityNotification.Announcement(message).post()
    }

    func clear(_ id: UUID) {
        if notice?.id == id { notice = nil }
    }
}

extension EnvironmentValues {
    @Entry var vaultFeedback: VaultOperationFeedback? = nil
}

extension View {
    func vaultOperationFeedback() -> some View { modifier(VaultFeedbackPresenter()) }
}

private struct VaultFeedbackPresenter: ViewModifier {
    @State private var feedback = VaultOperationFeedback()
    @State private var undoFailed = false

    func body(content: Content) -> some View {
        content
            .environment(\.vaultFeedback, feedback)
            .safeAreaInset(edge: .bottom, spacing: 0) {
                if let notice = feedback.notice {
                    HStack(spacing: Spacing.md) {
                        Label(notice.message, systemImage: "checkmark.circle")
                            .fixedSize(horizontal: false, vertical: true)
                        if let undo = notice.undo {
                            Button("撤销") {
                                feedback.clear(notice.id)
                                Task {
                                    do { try await undo() }
                                    catch { undoFailed = true }
                                }
                            }
                            .fontWeight(.semibold)
                            .frame(minHeight: 44)
                            .accessibilityIdentifier("vault.undo")
                        }
                    }
                    .font(.subheadline)
                    .padding(.horizontal, Spacing.lg)
                    .frame(minHeight: 44)
                    .glassStyle(in: Capsule())
                    .padding(.horizontal, Spacing.lg)
                    .padding(.bottom, Spacing.sm)
                    .task(id: notice.id) {
                        do { try await Task.sleep(until: notice.expires, clock: .continuous) }
                        catch { return }
                        feedback.clear(notice.id)
                    }
                }
            }
            .alert("无法撤销操作", isPresented: $undoFailed) {
                Button("好", role: .cancel) {}
            } message: { Text("请刷新保险库后重试。") }
    }
}
