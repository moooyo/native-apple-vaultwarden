import SwiftUI
import LocalAuthentication
import UIShared
import DesignSystem

public struct MacUnlockView: View {
    @State private var model: UnlockModel
    @State private var touchIDAvailable = false
    @State private var requestingTouchID = false
    @State private var confirmingLogout = false
    @State private var revealPassword = false
    @State private var masterFocused = true
    @Environment(\.locale) private var locale
    private let biometricsEnabled: Bool
    private let timeoutSignOutFailed: Bool
    private let onCredentialActivity: () -> Void
    private let onLoggedOut: () -> Void
    private let onUnlocked: () -> Void

    public init(model: UnlockModel, biometricsEnabled: Bool = false, timeoutSignOutFailed: Bool = false,
                onCredentialActivity: @escaping () -> Void = {}, onLoggedOut: @escaping () -> Void = {},
                onUnlocked: @escaping () -> Void) {
        _model = State(initialValue: model)
        self.biometricsEnabled = biometricsEnabled
        self.timeoutSignOutFailed = timeoutSignOutFailed
        self.onCredentialActivity = onCredentialActivity
        self.onLoggedOut = onLoggedOut
        self.onUnlocked = onUnlocked
    }

    private var isBusy: Bool { model.state == .unlocking || requestingTouchID }

    private var password: Binding<String> {
        Binding(get: { model.password }, set: { value in
            onCredentialActivity()
            model.password = value
        })
    }

    public var body: some View {
        MacAuthenticationForm(disablesFields: isBusy) {
            OpenVaultMark(size: 64)
                .overlay(alignment: .bottomTrailing) {
                    Image(systemName: "lock.fill")
                        .font(.callout.weight(.semibold)).padding(6)
                        .background(Palette.contentBackground, in: .circle)
                        .offset(x: 4, y: 4).accessibilityHidden(true)
                }
            VStack(spacing: Spacing.xs) {
                Text("OpenVault 已锁定").font(.title.bold()).accessibilityAddTraits(.isHeader)
                if let email = model.email {
                    Text(email).lineLimit(1).truncationMode(.middle).foregroundStyle(.secondary).privacySensitive()
                }
            }
            MacMasterPasswordRow(text: password, isRevealed: $revealPassword, isFocused: $masterFocused,
                                 accessibilityIdentifier: "unlock.password", onSubmit: unlock)
            if timeoutSignOutFailed {
                Label {
                    Text("Automatic sign-out did not complete. The vault is locked. To retry, select Sign Out.", tableName: "MacSettings")
                } icon: {
                    Image(systemName: "exclamationmark.triangle")
                }
                .font(.callout).foregroundStyle(.secondary)
            }
            if let message = model.errorMessage {
                Label(MacLocalization.text(message, locale: locale), systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(.red)
            }
        } footer: {
            Button("退出登录…") {
                onCredentialActivity()
                confirmingLogout = true
            }
            .buttonStyle(.link).disabled(isBusy)
            Spacer()
            if touchIDAvailable {
                Button(requestingTouchID ? "请将手指放在触控 ID 上" : "使用触控 ID 解锁", systemImage: "touchid", action: unlockWithTouchID)
                    .controlSize(.large)
                    .disabled(isBusy)
                    .accessibilityIdentifier("unlock.touch-id")
            }
            Button(action: unlock) {
                HStack {
                    if model.state == .unlocking && !requestingTouchID { ProgressView().controlSize(.small) }
                    Text(model.state == .unlocking && !requestingTouchID ? "正在验证…" : "解锁")
                        .frame(minWidth: 64)
                }
            }
            .keyboardShortcut(.defaultAction)
            .controlSize(.large)
            .disabled(model.password.isEmpty || isBusy)
            .accessibilityIdentifier("unlock.submit")
        }
        .task { await model.loadAccount() }
        .alert("退出登录？", isPresented: $confirmingLogout) {
            Button("取消", role: .cancel) {}
            Button("退出登录", role: .destructive) {
                onCredentialActivity()
                Task { if await model.logout() { onLoggedOut() } }
            }
        } message: { Text("下次访问保险库时需要重新登录。") }
        .modifier(MacTouchIDAvailability(isAvailable: $touchIDAvailable, enabled: biometricsEnabled))
        .onChange(of: model.state) { _, newValue in
            if newValue == .unlocked { onUnlocked() }
        }
    }

    private func unlock() {
        guard !model.password.isEmpty, !isBusy else { return }
        onCredentialActivity()
        revealPassword = false
        Task { await model.unlockWithPassword() }
    }

    private func unlockWithTouchID() {
        guard touchIDAvailable, !isBusy else { return }
        onCredentialActivity()
        revealPassword = false
        requestingTouchID = true
        Task {
            await model.unlockWithBiometrics(reason: MacLocalization.text("Unlock OpenVault with Touch ID", locale: locale))
            requestingTouchID = false
        }
    }
}

/// Refresh when a window or menu returns, not on each vault lock-state poll.
struct MacTouchIDAvailability: ViewModifier {
    @Binding var isAvailable: Bool
    var enabled = true
    @Environment(\.appearsActive) private var appearsActive
    @Environment(\.macTouchIDAvailabilityOverride) private var availabilityOverride

    func body(content: Content) -> some View {
        content
            .onAppear(perform: refresh)
            .onChange(of: enabled) { _, _ in refresh() }
            .onChange(of: appearsActive) { _, active in if active { refresh() } }
    }

    private func refresh() {
        guard enabled else { isAvailable = false; return }
        if let availabilityOverride { isAvailable = availabilityOverride; return }
        let context = LAContext()
        isAvailable = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            && context.biometryType == .touchID
    }
}

extension EnvironmentValues {
    @Entry var macTouchIDAvailabilityOverride: Bool?
}
