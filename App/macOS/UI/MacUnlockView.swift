import SwiftUI
import LocalAuthentication
import UIShared
import DesignSystem

public struct MacUnlockView: View {
    @State private var model: UnlockModel
    @State private var touchIDAvailable = false
    @State private var requestingTouchID = false
    @State private var confirmingLogout = false
    @FocusState private var passwordFocused: Bool
    private let biometricsEnabled: Bool
    private let onLoggedOut: () -> Void
    private let onUnlocked: () -> Void

    public init(model: UnlockModel, biometricsEnabled: Bool = false,
                onLoggedOut: @escaping () -> Void = {}, onUnlocked: @escaping () -> Void) {
        _model = State(initialValue: model)
        self.biometricsEnabled = biometricsEnabled
        self.onLoggedOut = onLoggedOut
        self.onUnlocked = onUnlocked
    }

    private var isUnlocking: Bool { model.state == .unlocking }

    public var body: some View {
        @Bindable var model = model

        VStack {
            Spacer()
            OpenVaultMark(size: 96)
                .overlay(alignment: .bottomTrailing) {
                    Image(systemName: "lock.fill")
                        .font(.body.weight(.semibold)).padding(8)
                        .background(Palette.contentBackground, in: .circle)
                        .offset(x: 6, y: 6).accessibilityHidden(true)
                }
            Text("OpenVault 已锁定").font(.title.bold()).accessibilityAddTraits(.isHeader)
                .padding(.top, Spacing.lg)
            if let email = model.email { Text(email).foregroundStyle(.secondary).privacySensitive() }
            if touchIDAvailable {
                VStack(spacing: 10) {
                    Button {
                        requestingTouchID = true
                        Task {
                            await model.unlockWithBiometrics(reason: "使用触控 ID 解锁 OpenVault")
                            requestingTouchID = false
                        }
                    } label: {
                        Image(systemName: "touchid").font(.system(size: 32, weight: .medium))
                            .frame(width: 60, height: 60)
                    }
                    .buttonStyle(.borderedProminent).buttonBorderShape(.circle)
                    .controlSize(.regular)
                    .accessibilityLabel("使用触控 ID 解锁")
                    .disabled(isUnlocking || requestingTouchID)
                    Text(requestingTouchID ? "请将手指放在触控 ID 上" : "使用触控 ID 解锁").font(.callout)
                }
                .padding(.vertical, Spacing.lg)
                HStack {
                    Rectangle().fill(Palette.separator).frame(height: 1)
                    Text("或输入主密码").fixedSize()
                    Rectangle().fill(Palette.separator).frame(height: 1)
                }
                    .foregroundStyle(.secondary).font(.caption).frame(width: 320)
            }
            ZStack(alignment: .trailing) {
                SecureField("主密码", text: $model.password)
                    .textContentType(.password).privacySensitive().onSubmit(unlock)
                    .textFieldStyle(.plain).focused($passwordFocused)
                    .padding(.leading, 12).padding(.trailing, 40)
                    .accessibilityIdentifier("unlock.password")
                Button("解锁", systemImage: "arrow.right.circle.fill", action: unlock)
                    .labelStyle(.iconOnly).buttonStyle(.plain).keyboardShortcut(.defaultAction)
                    .font(.title2).foregroundStyle(model.password.isEmpty || touchIDAvailable ? Color.secondary : .accentColor)
                    .padding(.trailing, 8)
                    .disabled(model.password.isEmpty).accessibilityIdentifier("unlock.submit")
            }
            .modifier(MacLoginFieldBorder(focused: passwordFocused))
            .disabled(isUnlocking).padding(.top, Spacing.sm).frame(width: 320)
            if isUnlocking && !requestingTouchID { ProgressView("正在验证…").controlSize(.small) }
            if let message = model.errorMessage {
                Label(message, systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(.red)
            }
            Spacer()
            Button("退出登录…") { confirmingLogout = true }
                .buttonStyle(.link).disabled(isUnlocking).padding(.bottom, Spacing.xl)
        }
        .padding(Spacing.lg)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(OpenVaultLockBackground())
        .task { await model.loadAccount() }
        .alert("退出登录？", isPresented: $confirmingLogout) {
            Button("取消", role: .cancel) {}
            Button("退出登录", role: .destructive) {
                Task { if await model.logout() { onLoggedOut() } }
            }
        } message: { Text("下次访问保险库时需要重新登录。") }
        .modifier(MacTouchIDAvailability(isAvailable: $touchIDAvailable, enabled: biometricsEnabled))
        .onChange(of: model.state) { _, newValue in
            if newValue == .unlocked { onUnlocked() }
        }
    }

    private func unlock() {
        guard !model.password.isEmpty, !isUnlocking else { return }
        Task { await model.unlockWithPassword() }
    }
}

/// Refresh when a window or menu returns, not on each vault lock-state poll.
struct MacTouchIDAvailability: ViewModifier {
    @Binding var isAvailable: Bool
    var enabled = true
    @Environment(\.appearsActive) private var appearsActive

    func body(content: Content) -> some View {
        content
            .onAppear(perform: refresh)
            .onChange(of: enabled) { _, _ in refresh() }
            .onChange(of: appearsActive) { _, active in if active { refresh() } }
    }

    private func refresh() {
        guard enabled else { isAvailable = false; return }
        let context = LAContext()
        isAvailable = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            && context.biometryType == .touchID
    }
}
