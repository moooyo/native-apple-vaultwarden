// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// TwoFactorView — the 2FA sheet shown when login reports `.needsTwoFactor`. Lets the
// user pick a provider (when more than one is offered) and enter a code. The OTP field
// uses `.oneTimeCode` content type so the system keychain/SMS autofill can suggest it.
//
// This view is presentation-only: it hands (code, provider, remember) back via the
// `onSubmit` closure; the parent's `LoginModel` performs the network round-trip.

import SwiftUI
import UIShared
import DesignSystem
import Networking

@available(iOS 26.0, *)
public struct TwoFactorView: View {
    let providers: [TwoFactorProvider]
    let isSubmitting: Bool
    let errorMessage: String?
    /// (code, provider, rememberDevice).
    let onSubmit: (String, TwoFactorProvider, Bool) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var code = ""
    @State private var rememberDevice = false
    @State private var selectedProvider: TwoFactorProvider
    @FocusState private var codeFocused: Bool

    public init(providers: [TwoFactorProvider], isSubmitting: Bool, errorMessage: String?,
                onSubmit: @escaping (String, TwoFactorProvider, Bool) -> Void) {
        self.providers = providers
        self.isSubmitting = isSubmitting
        self.errorMessage = errorMessage
        self.onSubmit = onSubmit
        _selectedProvider = State(initialValue: providers.first ?? .authenticator)
    }

    /// Code-entry providers we can drive with a text field in M1.
    private var codeEntryProviders: [TwoFactorProvider] {
        providers.filter { $0 == .authenticator || $0 == .email }
    }

    public var body: some View {
        NavigationStack {
            Form {
                if codeEntryProviders.count > 1 {
                    Section("Method") {
                        Picker("Method", selection: $selectedProvider) {
                            ForEach(codeEntryProviders, id: \.self) { provider in
                                Text(label(for: provider)).tag(provider)
                            }
                        }
                        .pickerStyle(.segmented)
                    }
                }

                Section {
                    TextField("Verification code", text: $code)
                        .textContentType(.oneTimeCode)
                        .keyboardType(.numberPad)
                        .font(Typography.code)
                        .focused($codeFocused)
                } header: {
                    Text(promptText)
                }

                Section {
                    Toggle("Remember this device", isOn: $rememberDevice)
                }

                if let errorMessage {
                    Section {
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(Palette.danger)
                            .font(Typography.rowSubtitle)
                    }
                }
            }
            .navigationTitle("Two-Step Login")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if isSubmitting {
                        ProgressView()
                    } else {
                        Button("Verify") {
                            onSubmit(code, selectedProvider, rememberDevice)
                        }
                        .disabled(code.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                }
            }
            .onAppear { codeFocused = true }
        }
    }

    private var promptText: String {
        switch selectedProvider {
        case .email: return "Enter the code emailed to you."
        case .authenticator: return "Enter the code from your authenticator app."
        default: return "Enter your verification code."
        }
    }

    private func label(for provider: TwoFactorProvider) -> String {
        switch provider {
        case .authenticator: return "Authenticator"
        case .email: return "Email"
        case .yubikey: return "YubiKey"
        case .webAuthn: return "Security Key"
        case .duo, .organizationDuo: return "Duo"
        case .u2f: return "U2F"
        case .remember: return "Remembered"
        }
    }
}
