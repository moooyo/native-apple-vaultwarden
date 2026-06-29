// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// LoginView — server URL + email + master password, submit. When `LoginModel`
// reports `.needsTwoFactor`, a `TwoFactorView` sheet collects the second factor.
//
// Standard `Form` controls get Liquid Glass automatically on recompile — we add NO
// custom `.glassEffect()` here. The password field is a `SecureField` (system-masked),
// so it is never rendered on clear glass.

import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import Networking

@available(iOS 26.0, *)
public struct LoginView: View {
    @State private var model: LoginModel
    /// Whether the 2FA sheet is presented (derived from the model's `.needsTwoFactor`).
    @State private var showTwoFactor = false
    @FocusState private var focusedField: Field?

    /// Called once the model reaches `.success` (the vault is now unlocked).
    private let onLoggedIn: () -> Void

    enum Field { case server, email, password }

    public init(model: LoginModel, onLoggedIn: @escaping () -> Void) {
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
        NavigationStack {
            Form {
                Section("Server") {
                    TextField("https://vault.example.com", text: $model.serverURL)
                        .textContentType(.URL)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .focused($focusedField, equals: .server)
                        .submitLabel(.next)
                        .onSubmit { focusedField = .email }
                }

                Section("Account") {
                    TextField("Email", text: $model.email)
                        .textContentType(.username)
                        .keyboardType(.emailAddress)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .focused($focusedField, equals: .email)
                        .submitLabel(.next)
                        .onSubmit { focusedField = .password }

                    SecureField("Master password", text: $model.password)
                        .textContentType(.password)
                        .focused($focusedField, equals: .password)
                        .submitLabel(.go)
                        .onSubmit { submit() }
                }

                if let message = model.errorMessage {
                    Section {
                        Label(message, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(Palette.danger)
                            .font(Typography.rowSubtitle)
                    }
                }

                Section {
                    Button(action: submit) {
                        HStack {
                            Spacer()
                            if isSubmitting {
                                ProgressView()
                            } else {
                                Text("Log In").fontWeight(.semibold)
                            }
                            Spacer()
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSubmit)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
                }
            }
            .navigationTitle("Tessera")
            .scrollDismissesKeyboard(.interactively)
        }
        .onChange(of: model.state) { _, newValue in
            switch newValue {
            case .needsTwoFactor:
                showTwoFactor = true
            case .success:
                showTwoFactor = false
                onLoggedIn()
            default:
                break
            }
        }
        .sheet(isPresented: $showTwoFactor) {
            TwoFactorView(
                providers: model.twoFactorProviders,
                isSubmitting: isSubmitting,
                errorMessage: model.errorMessage
            ) { code, provider, remember in
                Task { await model.submitTwoFactor(code: code, provider: provider, remember: remember) }
            }
            .interactiveDismissDisabled(true)
        }
    }

    private func submit() {
        guard canSubmit else { return }
        focusedField = nil
        Task { await model.submit() }
    }
}
