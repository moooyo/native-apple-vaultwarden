import SwiftUI
import LocalAuthentication
import UIShared
import DesignSystem

@available(iOS 27.0, *)
public struct UnlockView: View {
    @State private var model: UnlockModel
    private let onUnlocked: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var showingPassword = false
    @State private var pulse = false
    @State private var biometricName = "面容 ID"
    @State private var biometricSystemImage = "faceid"
    @FocusState private var passwordFocused: Bool

    public init(model: UnlockModel, onUnlocked: @escaping () -> Void) {
        _model = State(initialValue: model)
        self.onUnlocked = onUnlocked
    }

    private var isUnlocking: Bool { model.state == .unlocking }

    public var body: some View {
        ZStack {
            LinearGradient(colors: [.openVaultUnlockTop, .openVaultUnlockMiddle,
                                    .openVaultUnlockBottom],
                           startPoint: .top, endPoint: .bottom)
                .ignoresSafeArea()

            VStack(spacing: 0) {
                Spacer(minLength: 64)

                OpenVaultMark(size: 86)

                Text("OpenVault")
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundStyle(.white)
                    .padding(.top, 24)
                Text("保险库已锁定")
                    .font(.system(size: 15))
                    .foregroundStyle(.white.opacity(0.55))
                    .padding(.top, 6)

                Spacer()

                biometricButton

                if let message = model.errorMessage {
                    Text(message)
                        .font(.caption)
                        .foregroundStyle(Color(red: 1, green: 69 / 255, blue: 58 / 255))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, Spacing.xl)
                        .padding(.top, Spacing.md)
                }

                Spacer()

                Button { showingPassword = true } label: {
                    Text("使用主密码解锁")
                        .font(.headline)
                        .foregroundStyle(.white)
                        .frame(maxWidth: .infinity, minHeight: 50)
                }
                .glassStyle(in: Capsule())
                .padding(.horizontal, Spacing.xxl)

                Text("忘记主密码？请联系保险库管理员")
                    .font(.caption)
                    .foregroundStyle(.white.opacity(0.4))
                    .padding(.top, Spacing.md)
                    .padding(.bottom, Spacing.xl)
            }
            .frame(maxWidth: 560)
        }
        .preferredColorScheme(.dark)
        .onAppear {
            resolveBiometry()
            startPulseIfNeeded()
        }
        .onChange(of: reduceMotion) { _, _ in startPulseIfNeeded() }
        .onChange(of: model.state) { _, newValue in
            if newValue == .unlocked {
                showingPassword = false
                onUnlocked()
            }
        }
        .sheet(isPresented: $showingPassword) {
            passwordSheet
                .presentationDetents([.height(330), .medium])
                .presentationDragIndicator(.visible)
                .presentationBackground(Palette.groupedBackground)
        }
    }

    private var biometricButton: some View {
        Button {
            Task { await model.unlockWithBiometrics(reason: "解锁 OpenVault") }
        } label: {
            ZStack {
                Circle()
                    .stroke(.white.opacity(0.34), lineWidth: 1)
                    .scaleEffect(pulse ? 1.16 : 1)
                    .opacity(pulse ? 0.08 : 0.5)
                if isUnlocking {
                    ProgressView().tint(.white).controlSize(.large)
                } else {
                    Image(systemName: biometricSystemImage)
                        .font(.system(size: 38, weight: .regular))
                        .foregroundStyle(.white)
                }
            }
            .frame(width: 88, height: 88)
        }
        .buttonStyle(.plain)
        .glassStyle(in: Circle())
        .disabled(isUnlocking)
        .accessibilityLabel("使用\(biometricName)解锁")
    }

    private var passwordSheet: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: Spacing.lg) {
                    VStack(alignment: .leading, spacing: Spacing.xs) {
                        Text("主密码")
                            .font(.subheadline)
                            .foregroundStyle(Palette.secondaryText)
                        SecureField("输入主密码", text: $model.password)
                            .textContentType(.password)
                            .focused($passwordFocused)
                            .submitLabel(.go)
                            .onSubmit { unlockWithPassword() }
                            .padding(Spacing.md)
                            .background(Palette.contentBackground,
                                        in: RoundedRectangle(cornerRadius: CornerRadius.md,
                                                             style: .continuous))
                    }

                    if let message = model.errorMessage {
                        Label(message, systemImage: "exclamationmark.triangle.fill")
                            .font(.subheadline)
                            .foregroundStyle(Palette.danger)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }

                    Button(action: unlockWithPassword) {
                        Group {
                            if isUnlocking { ProgressView() }
                            else { Text("解锁").fontWeight(.semibold) }
                        }
                        .frame(maxWidth: .infinity, minHeight: 50)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.password.isEmpty || isUnlocking)
                }
                .padding(Spacing.xl)
            }
            .background(Palette.groupedBackground)
            .navigationTitle("使用主密码")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { showingPassword = false }
                }
            }
            .onAppear { passwordFocused = true }
        }
    }

    private func unlockWithPassword() {
        passwordFocused = false
        Task { await model.unlockWithPassword() }
    }

    private func startPulseIfNeeded() {
        pulse = false
        guard !reduceMotion else { return }
        withAnimation(.easeInOut(duration: 2.8).repeatForever(autoreverses: true)) {
            pulse = true
        }
    }

    private func resolveBiometry() {
        let context = LAContext()
        var error: NSError?
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        if context.biometryType == .touchID {
            biometricName = "触控 ID"
            biometricSystemImage = "touchid"
        }
    }
}
