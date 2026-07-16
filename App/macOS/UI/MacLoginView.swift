// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// MacLoginView — server URL + email + master password for macOS. A 2FA sheet
// (`MacTwoFactorView`) appears when the model reports `.needsTwoFactor`. Uses standard
// AppKit-backed SwiftUI controls (auto Liquid Glass); the password is a `SecureField`.

import SwiftUI
import UIShared
import DesignSystem
import Networking

@available(macOS 26.0, *)
public struct MacLoginView: View {
    @State private var model: LoginModel
    @State private var showTwoFactor = false
    private let onLoggedIn: (String) -> Void

    public init(model: LoginModel, onLoggedIn: @escaping (String) -> Void) {
        _model = State(initialValue: model)
        self.onLoggedIn = onLoggedIn
    }

    private var isSubmitting: Bool { model.state == .submitting }
    private var canSubmit: Bool {
        !model.serverURL.trimmingCharacters(in: .whitespaces).isEmpty &&
        !model.email.trimmingCharacters(in: .whitespaces).isEmpty &&
        !model.password.isEmpty && !isSubmitting
    }

    public var body: some View {
        VStack(spacing: Spacing.xl) {
            VStack(spacing: Spacing.xs) {
                Image(systemName: "lock.shield")
                    .font(.system(size: 44, weight: .semibold))
                    .foregroundStyle(Palette.accent)
                Text("Tessera").font(Typography.screenTitle)
            }

            Form {
                TextField("Server URL", text: $model.serverURL, prompt: Text("https://vault.example.com"))
                    .textContentType(.URL)
                TextField("Email", text: $model.email)
                    .textContentType(.username)
                SecureField("Master password", text: $model.password)
                    .textContentType(.password)
                    .onSubmit { submit() }
            }
            .formStyle(.grouped)
            .frame(maxWidth: 360)

            if let message = model.errorMessage {
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(Palette.danger)
                    .font(Typography.rowSubtitle)
            }

            Button(action: submit) {
                if isSubmitting {
                    ProgressView().controlSize(.small)
                } else {
                    Text("Log In").frame(maxWidth: 360)
                }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .disabled(!canSubmit)
        }
        .padding(Spacing.xxl)
        .onChange(of: model.state) { _, newValue in
            switch newValue {
            case .needsTwoFactor: showTwoFactor = true
            case .success: showTwoFactor = false; onLoggedIn(model.serverURL)
            default: break
            }
        }
        .sheet(isPresented: $showTwoFactor) {
            MacTwoFactorView(
                providers: model.twoFactorProviders,
                isSubmitting: isSubmitting,
                errorMessage: model.errorMessage,
                onResendEmail: { Task { await model.resendTwoFactorEmail() } }
            ) { code, provider, remember in
                Task { await model.submitTwoFactor(code: code, provider: provider, remember: remember) }
            }
        }
    }

    private func submit() {
        guard canSubmit else { return }
        Task { await model.submit() }
    }
}

// MARK: - 2FA sheet

@available(macOS 26.0, *)
struct MacTwoFactorView: View {
    let providers: [TwoFactorProvider]
    let isSubmitting: Bool
    let errorMessage: String?
    let onResendEmail: () -> Void
    let onSubmit: (String, TwoFactorProvider, Bool) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var code = ""
    @State private var rememberDevice = false
    @State private var selectedProvider: TwoFactorProvider

    init(providers: [TwoFactorProvider], isSubmitting: Bool, errorMessage: String?,
         onResendEmail: @escaping () -> Void,
         onSubmit: @escaping (String, TwoFactorProvider, Bool) -> Void) {
        self.providers = providers
        self.isSubmitting = isSubmitting
        self.errorMessage = errorMessage
        self.onResendEmail = onResendEmail
        self.onSubmit = onSubmit
        _selectedProvider = State(initialValue: providers.first ?? .authenticator)
    }

    private var codeEntryProviders: [TwoFactorProvider] {
        providers.filter { $0 == .authenticator || $0 == .email }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            Text("Two-Step Login").font(Typography.sectionTitle)

            if codeEntryProviders.count > 1 {
                Picker("Method", selection: $selectedProvider) {
                    ForEach(codeEntryProviders, id: \.self) { provider in
                        Text(provider == .email ? "Email" : "Authenticator").tag(provider)
                    }
                }
                .pickerStyle(.segmented)
            }

            TextField("Verification code", text: $code)
                .font(Typography.code)
                .onSubmit { submit() }

            if selectedProvider == .email {
                Button("Send a new code", action: onResendEmail)
                    .disabled(isSubmitting)
            }

            Toggle("Remember this device", isOn: $rememberDevice)

            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(Palette.danger)
                    .font(Typography.rowSubtitle)
            }

            HStack {
                Button("Cancel") { dismiss() }
                Spacer()
                if isSubmitting {
                    ProgressView().controlSize(.small)
                } else {
                    Button("Verify") { submit() }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                        .disabled(code.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
        .padding(Spacing.xl)
        .frame(width: 360)
    }

    private func submit() {
        onSubmit(code, selectedProvider, rememberDevice)
    }
}
