import Networking
import SwiftUI
import VaultRepository

@MainActor
struct AccountTwoFactorView: View {
    let repository: AccountTwoFactorManagement
    let isUnlocked: Bool

    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @State private var lease: AccountSessionLease?
    @State private var leaseEnded = false
    @State private var methods: [TwoFactorMethodStatus]?
    @State private var step: Step?
    @State private var confirmation: Action?
    @State private var password = ""
    @State private var code = ""
    @State private var address = ""
    @State private var keyName = ""
    @State private var canRegisterKey = false
    @State private var presentingSystemKeyPrompt = false
    @State private var feedback: LocalizedStringKey?
    @State private var failure: LocalizedStringKey?
    @State private var operationID: UUID?
    @State private var operation: Task<Void, Never>?

    private enum Step {
        case password(Action)
        case authenticatorSetup(AccountAuthenticatorSetup)
        case emailSetup(AccountEmailTwoFactorSetup)
        case keys([TwoFactorSecurityKey])
        case recovery(String?)
    }

    private enum Action {
        case setupAuthenticator, setupEmail, listKeys, registerKey, showRecoveryCode
        case removeAuthenticator, removeEmail, removeKey(TwoFactorSecurityKey)

        var title: LocalizedStringKey {
            switch self {
            case .setupAuthenticator: "Set Up Authenticator"
            case .setupEmail: "Set Up Email"
            case .listKeys: "View Security Keys"
            case .registerKey: "Register Security Key"
            case .showRecoveryCode: "Reveal Recovery Code"
            case .removeAuthenticator: "Remove Authenticator"
            case .removeEmail: "Remove Email"
            case .removeKey: "Remove Security Key"
            }
        }

        var isRemoval: Bool {
            switch self {
            case .removeAuthenticator, .removeEmail, .removeKey: true
            default: false
            }
        }
    }

    private var canPresent: Bool { isUnlocked && scenePhase == .active }
    private var isBusy: Bool { operationID != nil }

    var body: some View {
        platformLayout
            .task { await monitorSession() }
            .onChange(of: isUnlocked) { _, unlocked in if !unlocked { invalidateSession() } }
            .onChange(of: scenePhase) { _, phase in
                // An OS security key prompt can temporarily make this scene inactive.
                // Keep only that non-secret operation alive, never throughout backgrounding.
                if phase == .background || (phase == .inactive && !presentingSystemKeyPrompt) {
                    clearPresentation()
                } else if phase == .active, methods == nil, step == nil {
                    refresh()
                }
            }
            .onDisappear { clearPresentation() }
            .confirmationDialog("Confirm Account Action", isPresented: Binding(
                get: { confirmation != nil }, set: { if !$0 { confirmation = nil } }
            ), titleVisibility: .visible, presenting: confirmation) { action in
                Button(action.title, role: action.isRemoval ? .destructive : nil) { open(action) }
                Button("Cancel", role: .cancel) {}
            } message: { action in
                if case .removeKey(let key) = action {
                    Text("Remove \(keyTitle(key)) from this account? Other devices may need to verify again. If this is your last sign-in method, two-step login may turn off and organizations may restrict access.")
                } else if action.isRemoval {
                    Text("Remove this two-step login method from your account? Other devices may need to verify again. If this is your last method, two-step login may turn off and organizations may restrict access.")
                } else {
                    Text("Anyone with this code and your master password can turn off two-step login. Reveal it only somewhere private and keep it outside this vault.")
                }
            }
    }

    @ViewBuilder private var platformLayout: some View {
        #if os(macOS)
        VStack(alignment: .leading, spacing: 12) {
            Text("Two-step Login").font(.headline).accessibilityAddTraits(.isHeader)
                .padding(.horizontal, 20).padding(.top, 20)
            content
            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
            }
            .padding(.horizontal, 20).padding(.bottom, 16)
        }
        .frame(width: 560, height: 500)
        #else
        NavigationStack {
            content
                .navigationTitle("Two-step Login")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
                }
        }
        #endif
    }

    @ViewBuilder private var content: some View {
        if !isUnlocked || leaseEnded {
            ContentUnavailableView("Vault Is Locked", systemImage: "lock",
                                   description: Text("Unlock the vault and reopen Two-step Login."))
        } else if canPresent {
            Form {
                if let failure { Section { Label(failure, systemImage: "exclamationmark.circle").foregroundStyle(.secondary) } }
                if let feedback { Section { Text(feedback).foregroundStyle(.secondary) } }
                if isBusy { Section { ProgressView("Contacting server…") } }
                Group {
                    switch step {
                    case .password(let action): verificationForm(action)
                    case .authenticatorSetup(let setup): authenticatorForm(setup)
                    case .emailSetup(let setup): emailForm(setup)
                    case .keys(let keys): keyList(keys)
                    case .recovery(let recovery): recoveryDetails(recovery)
                    case nil: overview
                    }
                }
                .disabled(isBusy || lease == nil)
                if step != nil {
                    Section { Button("Back to Methods", action: backToMethods).disabled(isBusy) }
                }
            }
            .formStyle(.grouped)
            .accessibilityIdentifier("settings.two-step-login")
        } else {
            Color.clear.accessibilityHidden(true)
        }
    }

    @ViewBuilder private var overview: some View {
        if let methods {
            let authenticatorOn = methods.contains { $0.provider == .authenticator && $0.enabled }
            let emailOn = methods.contains { $0.provider == .email && $0.enabled }
            let keysOn = methods.contains { $0.provider == .webAuthn && $0.enabled }
            let otherMethods = methods.filter { ![.authenticator, .email, .webAuthn].contains($0.provider) }
            Section("Sign-in Methods") {
                LabeledContent("Authenticator App") {
                    methodStatus(authenticatorOn)
                    if authenticatorOn {
                        Button("Remove…", role: .destructive) { confirmation = .removeAuthenticator }.buttonStyle(.borderless)
                    } else {
                        Button("Set Up…") { open(.setupAuthenticator) }.buttonStyle(.borderless)
                    }
                }
                LabeledContent("Email") {
                    methodStatus(emailOn)
                    if emailOn {
                        Button("Remove…", role: .destructive) { confirmation = .removeEmail }.buttonStyle(.borderless)
                    } else {
                        Button("Set Up…") { open(.setupEmail) }.buttonStyle(.borderless)
                    }
                }
                LabeledContent("FIDO2 Security Keys") {
                    methodStatus(keysOn)
                    if keysOn { Button("View Keys…") { open(.listKeys) }.buttonStyle(.borderless) }
                    if canRegisterKey { Button("Register…") { open(.registerKey) }.buttonStyle(.borderless) }
                }
                ForEach(otherMethods) { method in
                    LabeledContent(methodTitle(method)) { methodStatus(method.enabled) }
                }
            }
            Section {
                Button("Reveal Recovery Code…") { confirmation = .showRecoveryCode }
            } header: {
                Text("Recovery")
            } footer: {
                Text("Keep your recovery code somewhere safe outside this vault in case you lose access to your sign-in methods.")
            }
            Section {
                Button("Refresh Methods", action: refresh)
            } footer: {
                if canRegisterKey {
                    Text("Use the web vault to manage other sign-in methods. Native email setup requires server mail with six-digit codes.")
                } else {
                    Text("Use your server’s web vault to register a FIDO2 security key or manage other sign-in methods. Native email setup requires server mail with six-digit codes.")
                }
            }
        } else if !isBusy {
            Section { Button("Refresh Methods", action: refresh) }
        }
    }

    private func methodStatus(_ enabled: Bool) -> some View {
        Text(enabled ? "On" : "Not Active").foregroundStyle(.secondary)
    }

    private func methodTitle(_ method: TwoFactorMethodStatus) -> LocalizedStringKey {
        switch method.provider {
        case .duo: "Duo"
        case .organizationDuo: "Organization Duo"
        case .yubikey: "YubiKey OTP"
        case .u2f: "Legacy U2F"
        case .remember: "Remembered Device"
        default: "Other Method (\(method.type))"
        }
    }

    @ViewBuilder private func verificationForm(_ action: Action) -> some View {
        Section {
            if case .registerKey = action {
                TextField("Security key name", text: $keyName).privacySensitive()
            }
            if case .setupEmail = action {
                TextField("Email for sign-in codes", text: $address)
                    .textContentType(.emailAddress)
                    #if os(iOS)
                    .keyboardType(.emailAddress)
                    .textInputAutocapitalization(.never)
                    #endif
                    .autocorrectionDisabled()
                    .privacySensitive()
            }
            passwordField
            Button(action.title, role: action.isRemoval ? .destructive : nil) { verify(action) }
                .disabled(!canVerify(action))
        } header: {
            Text(action.title)
        } footer: {
            if case .registerKey = action {
                Text("Verify your master password, then follow the system prompt to register a physical security key.")
            } else {
                Text("Enter your master password to verify this account. Your password is not saved.")
            }
        }
    }

    private func canVerify(_ action: Action) -> Bool {
        guard !password.isEmpty else { return false }
        switch action {
        case .setupEmail: return !address.isEmpty
        case .registerKey: return canRegisterKey && !keyName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        default: return true
        }
    }

    private var passwordField: some View {
        SecureField("Master password", text: $password)
            .textContentType(.password)
            .privacySensitive()
            .accessibilityIdentifier("settings.two-step-login.password")
    }

    private var codeField: some View {
        TextField("Verification code", text: $code)
            .textContentType(.oneTimeCode)
            #if os(iOS)
            .keyboardType(.numberPad)
            #endif
            .monospacedDigit()
            .privacySensitive()
            .accessibilityIdentifier("settings.two-step-login.code")
    }

    private var canActivate: Bool {
        !password.isEmpty && code.utf8.count == 6 && code.utf8.allSatisfy { (48...57).contains($0) }
    }

    @ViewBuilder private func authenticatorForm(_ setup: AccountAuthenticatorSetup) -> some View {
        Section("Authenticator Setup Key") {
            Text("In your authenticator app, add this account manually using the setup key. Choose a time-based code (SHA-1, six digits, 30 seconds).")
            secretText(setup.secret)
        }
        Section {
            codeField
            passwordField
            Button("Enable Authenticator") { activate(setup) }.disabled(!canActivate)
        } footer: {
            Text("Enter a current code from your authenticator and verify your master password again before turning on this method.")
        }
    }

    private func emailForm(_ setup: AccountEmailTwoFactorSetup) -> some View {
        Section {
            Text("Enter the code sent to \(setup.address). Use only a code delivered to this address.")
                .privacySensitive()
            codeField
            passwordField
            Button("Enable Email") { activate(setup) }.disabled(!canActivate)
        } header: {
            Text("Confirm Email Address")
        } footer: {
            Text("Enter the full six-digit code. If your server uses a different length, set this up in the web vault instead.")
        }
    }

    private func keyList(_ keys: [TwoFactorSecurityKey]) -> some View {
        Section {
            if keys.isEmpty { Text("No security keys are configured.") }
            ForEach(keys) { key in
                LabeledContent {
                    Button("Remove…", role: .destructive) { confirmation = .removeKey(key) }.buttonStyle(.borderless)
                } label: {
                    Text(verbatim: keyTitle(key)).privacySensitive()
                }
            }
        } header: {
            Text("Registered Security Keys")
        } footer: {
            if !canRegisterKey { Text("Register new security keys in your server’s web vault.") }
        }
    }

    private func recoveryDetails(_ recovery: String?) -> some View {
        Section {
            if let recovery {
                secretText(recovery)
                Button("Hide Recovery Code") { returnToOverview() }
            } else {
                Text("The server has not generated a recovery code for this account.").foregroundStyle(.secondary)
            }
        } header: {
            Text("Recovery Code")
        } footer: {
            Text("Anyone with this code and your master password can turn off two-step login. Keep it private and outside this vault.")
        }
    }

    private func secretText(_ value: String) -> some View {
        Text(verbatim: value)
            .font(.system(.body, design: .monospaced))
            .textSelection(.disabled)
            .privacySensitive()
    }

    private func keyTitle(_ key: TwoFactorSecurityKey) -> String {
        key.name.isEmpty ? String(localized: "Security Key \(key.id)") : key.name
    }

    private func monitorSession() async {
        guard isUnlocked, !leaseEnded else { return }
        let active = await repository.unlockedSessionLease()
        guard !Task.isCancelled else { return }
        guard let active, lease == nil || lease == active else { invalidateSession(); return }
        lease = active
        let environment = try? await repository.securityKeyRegistrationEnvironment(for: active)
        guard !Task.isCancelled, lease == active, !leaseEnded else { return }
        canRegisterKey = environment.map { WebAuthnSecurityKeyRegistration.isAvailable(for: $0) } == true
        refresh()
        while !Task.isCancelled {
            do { try await Task.sleep(for: .milliseconds(250)) } catch { return }
            let current = await repository.unlockedSessionLease()
            guard !Task.isCancelled else { return }
            guard current == active else { invalidateSession(); return }
        }
    }

    private func open(_ action: Action) {
        guard canPresent, lease != nil, !isBusy else { return }
        resetFields()
        step = .password(action)
    }

    private func refresh() {
        guard let lease else { return }
        run { try await loadMethods(for: lease) }
    }

    private func loadMethods(for lease: AccountSessionLease) async throws {
        methods = nil
        let result = try await repository.methods(for: lease)
        try await validatePresentation(for: lease)
        methods = result
    }

    private func verify(_ action: Action) {
        guard let lease, canVerify(action), !isBusy else { return }
        let suppliedPassword = password
        let suppliedAddress = address
        let suppliedKeyName = keyName
        password = ""
        run {
            switch action {
            case .setupAuthenticator:
                let setup = try await repository.beginAuthenticatorSetup(for: lease, password: suppliedPassword)
                try await validatePresentation(for: lease)
                step = .authenticatorSetup(setup)
            case .setupEmail:
                let setup = try await repository.beginEmailSetup(address: suppliedAddress, for: lease, password: suppliedPassword)
                try await validatePresentation(for: lease)
                address = ""
                step = .emailSetup(setup)
            case .listKeys:
                let keys = try await repository.securityKeys(for: lease, password: suppliedPassword)
                try await validatePresentation(for: lease)
                step = .keys(keys)
            case .registerKey:
                let keys = try await repository.registerSecurityKey(
                    name: suppliedKeyName, for: lease, password: suppliedPassword,
                    isAvailable: { await WebAuthnSecurityKeyRegistration.isAvailable(for: $0) },
                    authorize: authorizeRegistration
                )
                try await validatePresentation(for: lease, allowInactive: true)
                returnToOverview()
                methods = nil
                step = .keys(keys)
                feedback = "Security key registered. Save your recovery code outside this vault."
            case .showRecoveryCode:
                let recovery = try await repository.revealRecoveryCode(for: lease, password: suppliedPassword)
                try await validatePresentation(for: lease)
                step = .recovery(recovery)
            case .removeAuthenticator:
                try await repository.removeAuthenticator(for: lease, password: suppliedPassword)
                try await finishChange(for: lease, feedback: "Authenticator removed.")
            case .removeEmail:
                try await repository.removeEmail(for: lease, password: suppliedPassword)
                try await finishChange(for: lease, feedback: "Email removed.")
            case .removeKey(let key):
                _ = try await repository.removeSecurityKey(key, for: lease, password: suppliedPassword)
                try await finishChange(for: lease, feedback: "Security key removed.")
            }
        }
    }

    private func authorizeRegistration(_ challenge: TwoFactorSecurityKeyRegistrationChallenge, _ environment: ServerEnvironment)
        async throws -> TwoFactorSecurityKeyAttestation {
        guard canPresent, !leaseEnded else { throw CancellationError() }
        presentingSystemKeyPrompt = true
        defer { presentingSystemKeyPrompt = false }
        return try await WebAuthnSecurityKeyRegistration.authorize(challenge, environment: environment)
    }

    private func activate(_ setup: AccountAuthenticatorSetup) {
        submitCode { lease, suppliedPassword, suppliedCode in
            try await repository.enableAuthenticator(setup, code: suppliedCode, password: suppliedPassword, for: lease)
            try await finishChange(for: lease, feedback: "Authenticator enabled. Save your recovery code outside this vault.")
        }
    }

    private func activate(_ setup: AccountEmailTwoFactorSetup) {
        submitCode { lease, suppliedPassword, suppliedCode in
            try await repository.enableEmail(setup, code: suppliedCode, password: suppliedPassword, for: lease)
            try await finishChange(for: lease, feedback: "Email enabled. Save your recovery code outside this vault.")
        }
    }

    private func submitCode(_ action: @escaping @MainActor (AccountSessionLease, String, String) async throws -> Void) {
        guard let lease, !password.isEmpty, !code.isEmpty, !isBusy else { return }
        let suppliedPassword = password
        let suppliedCode = code
        password = ""
        code = ""
        run { try await action(lease, suppliedPassword, suppliedCode) }
    }

    private func validatePresentation(for expected: AccountSessionLease, allowInactive: Bool = false) async throws {
        let current = await repository.unlockedSessionLease()
        try Task.checkCancellation()
        guard canPresent || (allowInactive && isUnlocked && scenePhase == .inactive) else { throw CancellationError() }
        guard current == expected, lease == expected else { throw RepositoryError.locked }
    }

    private func finishChange(for lease: AccountSessionLease, feedback message: LocalizedStringKey) async throws {
        try await validatePresentation(for: lease)
        returnToOverview()
        feedback = message
        try await loadMethods(for: lease)
    }

    private func run(_ work: @escaping @MainActor () async throws -> Void) {
        guard canPresent, lease != nil, !leaseEnded, !isBusy else { return }
        let id = UUID()
        operationID = id
        failure = nil
        feedback = nil
        operation = Task {
            defer {
                if operationID == id { operationID = nil; operation = nil }
            }
            do { try await work() }
            catch {
                guard !Task.isCancelled, operationID == id, !(error is CancellationError) else { return }
                presentFailure(error)
            }
        }
    }

    private func presentFailure(_ error: Error) {
        switch error {
        case RepositoryError.locked: invalidateSession(); return
        case RepositoryError.authenticationFailed: failure = "The master password is incorrect."
        case RepositoryError.notAuthenticated: failure = "The server session is no longer available. Sign in again to manage two-step login."
        case AccountTwoFactorError.busy: failure = "Another account security action is in progress. Try again shortly."
        case AccountTwoFactorError.invalidCode: failure = "Enter the digits from the latest verification code."
        case AccountTwoFactorError.invalidEmail: failure = "Enter a valid email address."
        case AccountTwoFactorError.invalidKeyName: failure = "Enter a shorter security key name without control characters."
        case AccountTwoFactorError.securityKeyLimit: failure = "No more security keys can be registered in this app."
        case WebAuthnSecondFactorError.unsupported:
            canRegisterKey = false
            returnToOverview()
            failure = "Native registration is unavailable for this site. Use your server’s web vault."
        case WebAuthnSecondFactorError.invalidAssertion, WebAuthnSecondFactorError.authorizationFailed:
            failure = "The security key could not be registered. Try again, or use your server’s web vault."
        case AccountTwoFactorError.setupExpired:
            returnToOverview()
            failure = "Setup has expired. Start setup again to get a new code or key."
        case AccountTwoFactorError.configurationChanged:
            returnToOverview()
            methods = nil
            failure = "The configuration changed. Refresh your methods before trying again."
        case AccountTwoFactorError.unsupportedServer: failure = "This server does not support the required account security protocol. Use its web vault."
        case AccountTwoFactorError.serverRejected: failure = "The server rejected the request. Check the latest code or your server configuration."
        case AccountTwoFactorError.changeUnconfirmed:
            returnToOverview()
            methods = nil
            failure = "The server did not confirm this change. Refresh your methods before trying again."
        default: failure = "Could not reach or read the server. Try again."
        }
    }

    private func resetFields() {
        password = ""
        code = ""
        address = ""
        keyName = ""
        confirmation = nil
        feedback = nil
        failure = nil
    }

    private func returnToOverview() {
        step = nil
        resetFields()
    }

    private func backToMethods() {
        returnToOverview()
        if methods == nil { refresh() }
    }

    private func clearPresentation() {
        operation?.cancel()
        operation = nil
        operationID = nil
        methods = nil
        returnToOverview()
    }

    private func invalidateSession() {
        leaseEnded = true
        clearPresentation()
        lease = nil
    }
}
