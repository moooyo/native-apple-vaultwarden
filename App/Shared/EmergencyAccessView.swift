import Foundation
import Networking
import SwiftUI
import VaultModels
import VaultRepository

@MainActor
struct EmergencyAccessView: View {
    let repository: EmergencyAccessRepository
    let sessionIsUnlocked: Bool

    init(repository: EmergencyAccessRepository, sessionIsUnlocked: Bool = true) {
        self.repository = repository
        self.sessionIsUnlocked = sessionIsUnlocked
    }

    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @State private var lease: AccountSessionLease?
    @State private var listing: EmergencyAccessListing?
    @State private var page = Page.contacts
    @State private var email = ""
    @State private var waitTime = 7
    @State private var invitationID = ""
    @State private var privateInput = ""
    @State private var confirmation: ActionReview?
    @State private var grantorScopeID: UUID?
    @State private var work: Task<Void, Never>?
    @State private var workID: UUID?
    @State private var feedback: String?

    private static let actions: [EmergencyAccessAction] = [.reinvite, .request, .approve, .reject, .revoke]

    private enum Page {
        case contacts
        case invite
        case edit(EmergencyAccessContact)
        case accept
        case confirm(EmergencyAccessConfirmation)
        case vault(EmergencyAccessContact, EmergencyAccessViewIndex)
        case password(EmergencyAccessContact, EmergencyAccessItemSummary)
        case item(EmergencyAccessItemDetails)

        var displaysGrantorData: Bool {
            switch self {
            case .vault, .password, .item: true
            default: false
            }
        }
    }

    private struct ActionReview {
        let action: EmergencyAccessAction
        let contact: EmergencyAccessContact
    }

    var body: some View {
        NavigationStack {
            contentForm
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Done") { reset(); dismiss() }
                    }
                }
        }
        #if os(macOS)
        .frame(minWidth: 520, minHeight: 470)
        #endif
    }

    private var contentForm: some View {
        Form {
            if !sessionIsUnlocked {
                Text("Unlock your vault to manage emergency access.")
            } else if scenePhase == .active {
                contents
                if workID != nil { ProgressView("Contacting the server…").controlSize(.small) }
                if let feedback { Text(feedback).font(.footnote) }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Emergency Access")
        .privacySensitive()
        .onAppear { if sessionIsUnlocked && scenePhase == .active { open() } }
        .onChange(of: sessionIsUnlocked) { _, unlocked in
            reset()
            if unlocked && scenePhase == .active { open() }
        }
        .onChange(of: scenePhase) { _, phase in
            // Neither secret inputs nor decrypted grantor data may survive focus loss.
            reset()
            if phase == .active && sessionIsUnlocked { open() }
        }
        .onDisappear { reset() }
        .task(id: grantorScopeID) { [scope = grantorScopeID] in
            guard let scope, let lease else { return }
            let expiry = ContinuousClock.now + .seconds(60)
            do {
                while !Task.isCancelled && scope == grantorScopeID {
                    let active = await repository.unlockedSessionLease()
                    guard !Task.isCancelled, scope == grantorScopeID else { return }
                    guard active == lease else { reset(); return }
                    if ContinuousClock.now >= expiry { closePage(); return }
                    try await Task.sleep(for: .seconds(1))
                }
            } catch { }
        }
        .confirmationDialog("Confirm Emergency Access Action", isPresented: Binding(
            get: { confirmation != nil },
            set: { if !$0 { confirmation = nil } }
        ), titleVisibility: .visible, presenting: confirmation) { review in
            Button(actionTitle(review.action, direction: review.contact.direction), role: actionRole(review.action)) {
                confirmation = nil
                mutate { lease in try await repository.perform(review.action, on: review.contact, lease: lease) }
            }
            Button("Cancel", role: .cancel) { confirmation = nil }
        } message: { review in
            Text(verbatim: actionMessage(review))
        }
    }

    @ViewBuilder private var contents: some View {
        if case .contacts = page {
            contactSections
        } else {
            Button("Back to Emergency Access", systemImage: "chevron.backward") { closePage() }
            switch page {
            case .contacts: EmptyView()
            case .invite: inviteSection
            case .edit(let contact): editSection(contact)
            case .accept: acceptSection
            case .confirm(let review): confirmSection(review)
            case .vault(let contact, let index): vaultSection(contact, index)
            case .password(let contact, let item): passwordSection(contact, item)
            case .item(let item): itemSection(item)
            }
        }
    }

    @ViewBuilder private var contactSections: some View {
        Section {
            Button("Refresh", systemImage: "arrow.clockwise") { open() }.disabled(workID != nil)
            Button("Invite Contact", systemImage: "person.badge.plus") {
                waitTime = 7
                changePage(.invite)
            }
            .disabled(lease == nil || listing == nil || workID != nil)
            Button("Accept Invitation", systemImage: "envelope.open") { changePage(.accept) }
                .disabled(lease == nil || listing == nil || workID != nil)
        } footer: {
            Text("OpenVault supports read-only emergency access to personal vaults. Set up or use account takeover in the Web Vault on the same server.")
        }
        if let listing {
            contactSection("Trusted Contacts", contacts: listing.trusted)
            contactSection("Access Granted to Me", contacts: listing.granted)
            if listing.trusted.isEmpty && listing.granted.isEmpty {
                Text("The server returned no emergency access records. This also happens when the feature is disabled on the server.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
    }

    private func contactSection(_ title: LocalizedStringKey, contacts: [EmergencyAccessContact]) -> some View {
        Section(title) {
            if contacts.isEmpty { Text("No records").foregroundStyle(.secondary) }
            ForEach(contacts) { contact in
                VStack(alignment: .leading, spacing: 6) {
                    if let name = contact.name, !name.isEmpty, name != contact.email {
                        Text(verbatim: name).font(.headline)
                    }
                    Text(verbatim: contact.email)
                    Text("\(statusTitle(contact.status)) · \(typeTitle(contact.type))")
                        .font(.subheadline).foregroundStyle(.secondary)
                    Text("Server wait period: \(contact.waitTimeDays) days")
                        .font(.footnote).foregroundStyle(.secondary)
                    if contact.status == .recoveryInitiated {
                        Text("This request is pending. Refresh to check whether the server has approved it.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    if contact.type == .takeover {
                        Text("This grant permits account takeover. Use the Web Vault to manage takeover.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    Menu("Manage") { contactActions(contact) }
                        .disabled(workID != nil)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    @ViewBuilder private func contactActions(_ contact: EmergencyAccessContact) -> some View {
        if EmergencyAccessRepository.canEdit(contact) {
            Button("Edit Wait Period") {
                let range = EmergencyAccessRepository.waitTimeRange
                waitTime = min(range.upperBound, max(range.lowerBound, contact.waitTimeDays))
                changePage(.edit(contact))
            }
        }
        if EmergencyAccessRepository.canConfirm(contact) {
            Button("Verify Fingerprint and Confirm") { prepareConfirmation(contact) }
        }
        if EmergencyAccessRepository.canView(contact) {
            Button("View Read-Only Vault") { openVault(contact) }
        }
        ForEach(Self.actions, id: \.self) { action in
            if action.isAvailable(for: contact) {
                Button(actionTitle(action, direction: contact.direction), role: actionRole(action)) {
                    confirmation = ActionReview(action: action, contact: contact)
                }
            }
        }
    }

    private var inviteSection: some View {
        Section("Invite a Read-Only Contact") {
            TextField("Contact Email", text: $email)
                .autocorrectionDisabled()
                #if os(iOS)
                .textInputAutocapitalization(.never)
                .keyboardType(.emailAddress)
                #endif
            waitTimeControl
            Text("After the contact accepts, verify their fingerprint with them before confirming. Once a request is approved, they can view your personal vault.")
                .font(.footnote).foregroundStyle(.secondary)
            Button("Send Read-Only Invitation") {
                let address = email
                let wait = waitTime
                mutate { lease in try await repository.invite(email: address, waitTimeDays: wait, lease: lease) }
            }
            .disabled(email.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || workID != nil)
        }
    }

    private func editSection(_ contact: EmergencyAccessContact) -> some View {
        Section("Edit Wait Period") {
            Text(verbatim: contact.email)
            waitTimeControl
            Text("A shorter wait period may give the contact access sooner. Pending or approved requests cannot be edited here.")
                .font(.footnote).foregroundStyle(.secondary)
            Button("Save Wait Period") {
                let wait = waitTime
                mutate { lease in try await repository.edit(contact, waitTimeDays: wait, lease: lease) }
            }
            .disabled(waitTime == contact.waitTimeDays || workID != nil)
        }
    }

    private var waitTimeControl: some View {
        Stepper(value: $waitTime, in: EmergencyAccessRepository.waitTimeRange) {
            Text("Wait period: \(waitTime) days")
        }
    }

    private var acceptSection: some View {
        Section("Accept Invitation") {
            Text("Sign in to the account that received the invitation. Enter the id and token separately from the email link; do not paste the full link here. You can also accept from the email in the Web Vault.")
                .font(.footnote).foregroundStyle(.secondary)
            TextField("Invitation ID (id)", text: $invitationID)
                .monospaced()
                .autocorrectionDisabled()
                #if os(iOS)
                .textInputAutocapitalization(.never)
                #endif
            SecureField("Invitation Token (token)", text: $privateInput)
                .autocorrectionDisabled()
            Button("Accept This Invitation") {
                guard let id = UUID(uuidString: invitationID.trimmingCharacters(in: .whitespacesAndNewlines)) else { return }
                let token = privateInput
                privateInput = ""
                mutate { lease in try await repository.accept(invitationID: id, token: token, lease: lease) }
            }
            .disabled(UUID(uuidString: invitationID.trimmingCharacters(in: .whitespacesAndNewlines)) == nil
                      || privateInput.isEmpty || workID != nil)
        }
    }

    private func confirmSection(_ review: EmergencyAccessConfirmation) -> some View {
        Section {
            Text(verbatim: review.contact.email)
            Text(verbatim: review.fingerprint).monospaced().fixedSize(horizontal: false, vertical: true)
            Text("Ask the contact for their Web Vault account fingerprint over a separate, trusted channel. Enter the five words they provide, separated by hyphens. Do not confirm if they differ.")
                .font(.footnote).foregroundStyle(.secondary)
            TextField("Fingerprint Provided by Contact", text: $privateInput)
                .autocorrectionDisabled()
                #if os(iOS)
                .textInputAutocapitalization(.never)
                #endif
            Button("Confirm Read-Only Grant") {
                let fingerprint = privateInput
                privateInput = ""
                mutate { _ in try await repository.confirm(review, verifiedFingerprint: fingerprint) }
            }
            .disabled(privateInput.isEmpty || workID != nil)
        } header: {
            Text("Verify Contact Fingerprint")
        } footer: {
            Text("Confirming encrypts your vault key for this contact. If the server later approves an emergency request, the contact can read your personal vault.")
        }
    }

    private func vaultSection(_ contact: EmergencyAccessContact, _ index: EmergencyAccessViewIndex) -> some View {
        Section {
            Text(verbatim: contact.email)
            if index.items.isEmpty { Text("No items can be viewed here.").foregroundStyle(.secondary) }
            ForEach(index.items) { item in
                Button {
                    changePage(.password(contact, item))
                } label: {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(verbatim: item.name)
                        Text(item.isArchived ? "Archived · \(itemTypeTitle(item.type))" : itemTypeTitle(item.type))
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
            }
            if index.unsupportedItemCount > 0 {
                Text("Items that could not be read: \(index.unsupportedItemCount). Try the Web Vault.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        } header: {
            Text("Read-Only Vault")
        } footer: {
            Text("Only supported fields of personal items are displayed. Use the Web Vault for attachments, passkeys, password history, trash, and other encryption formats. Items are not added to your own vault.")
        }
    }

    private func passwordSection(_ contact: EmergencyAccessContact, _ item: EmergencyAccessItemSummary) -> some View {
        Section("Verify to View") {
            Text(verbatim: item.name).font(.headline)
            Text("Enter your current account’s master password. After verifying it locally, OpenVault checks the grant with the server again.")
                .font(.footnote).foregroundStyle(.secondary)
            SecureField("Your Master Password", text: $privateInput)
            Button("Verify and Open Item") {
                let password = privateInput
                privateInput = ""
                runWithLease { lease, workID in
                    let details = try await repository.readItem(id: item.id, from: contact, lease: lease, masterPassword: password)
                    try await requirePublish(lease, workID: workID)
                    changePage(.item(details))
                }
            }
            .disabled(privateInput.isEmpty || workID != nil)
        }
    }

    private func itemSection(_ item: EmergencyAccessItemDetails) -> some View {
        Section {
            Text(verbatim: item.name).font(.headline)
            if item.fields.isEmpty { Text("No fields to display.").foregroundStyle(.secondary) }
            ForEach(Array(item.fields.enumerated()), id: \.offset) { _, field in
                EmergencyAccessFieldRow(field: field)
            }
        } header: {
            Text("Read-Only Item")
        } footer: {
            Text("Details are cleared when you close the page, leave the app, lock the vault, or reach the 60-second viewing limit.")
        }
    }

    private func open() {
        schedule { workID in
            listing = nil
            guard let activeLease = await repository.unlockedSessionLease() else { throw EmergencyAccessError.sessionChanged }
            guard !Task.isCancelled, self.workID == workID, scenePhase == .active else { throw CancellationError() }
            lease = activeLease
            try await refresh(activeLease, workID: workID)
        }
    }

    private func refresh(_ lease: AccountSessionLease, workID: UUID) async throws {
        let result = try await repository.list(lease: lease)
        try await requirePublish(lease, workID: workID)
        listing = result
    }

    private func prepareConfirmation(_ contact: EmergencyAccessContact) {
        runWithLease { lease, workID in
            let prepared = try await repository.prepareConfirmation(for: contact, lease: lease)
            try await requirePublish(lease, workID: workID)
            changePage(.confirm(prepared))
        }
    }

    private func openVault(_ contact: EmergencyAccessContact) {
        runWithLease { lease, workID in
            let index = try await repository.viewIndex(for: contact, lease: lease)
            try await requirePublish(lease, workID: workID)
            changePage(.vault(contact, index))
        }
    }

    private func mutate(_ action: @escaping @MainActor (AccountSessionLease) async throws -> Void) {
        runWithLease { lease, workID in
            try await action(lease)
            try await requirePublish(lease, workID: workID)
            email = ""
            invitationID = ""
            changePage(.contacts)
            listing = nil
            try await refresh(lease, workID: workID)
        }
    }

    private func runWithLease(_ action: @escaping @MainActor (AccountSessionLease, UUID) async throws -> Void) {
        schedule { workID in
            guard let lease else { throw EmergencyAccessError.sessionChanged }
            try await action(lease, workID)
        }
    }

    private func schedule(_ action: @escaping @MainActor (UUID) async throws -> Void) {
        guard workID == nil, sessionIsUnlocked, scenePhase == .active else { return }
        let id = UUID()
        workID = id
        feedback = nil
        work = Task {
            defer {
                if workID == id { workID = nil; work = nil }
            }
            do { try await action(id) }
            catch is CancellationError { }
            catch {
                guard !Task.isCancelled, workID == id else { return }
                showError(error)
            }
        }
    }

    private func requirePublish(_ lease: AccountSessionLease, workID: UUID) async throws {
        guard await repository.unlockedSessionLease() == lease else { throw EmergencyAccessError.sessionChanged }
        guard !Task.isCancelled, self.workID == workID, scenePhase == .active else { throw CancellationError() }
    }

    private func changePage(_ next: Page) {
        privateInput = ""
        confirmation = nil
        feedback = nil
        if next.displaysGrantorData { grantorScopeID = grantorScopeID ?? UUID() }
        else { grantorScopeID = nil }
        page = next
    }

    private func closePage() {
        work?.cancel()
        work = nil
        workID = nil
        email = ""
        invitationID = ""
        changePage(.contacts)
        // Cancellation after dispatch cannot undo a server mutation. Reload before presenting actions again.
        open()
    }

    private func reset() {
        work?.cancel()
        work = nil
        workID = nil
        email = ""
        invitationID = ""
        lease = nil
        listing = nil
        changePage(.contacts)
    }

    private func showError(_ error: Error) {
        let issue = error as? EmergencyAccessError ?? .unavailable
        switch issue {
        case .sessionChanged, .authorizationRequired:
            lease = nil
            listing = nil
            changePage(.contacts)
        case .contactChanged, .serverRejected, .invalidResponse, .unavailable, .actionUnavailable:
            listing = nil
            changePage(.contacts)
        default:
            break
        }
        feedback = switch issue {
        case .sessionChanged: "The vault locked or the session changed. Unlock and refresh."
        case .authorizationRequired: "The server rejected the current session. Sign in again to continue."
        case .invalidEmail: "Enter a valid email address other than your own."
        case .invalidWaitTime: "The wait period must be 1–90 days."
        case .invalidInvitation: "The invitation token is not valid. Check the email or accept the invitation in the Web Vault."
        case .contactChanged: "The grant changed on the server. Refresh and review it again."
        case .actionUnavailable: "This action is unavailable for the current status or grant type. Refresh or use the Web Vault."
        case .fingerprintMismatch: "The fingerprints do not match. No grant was sent. Check with your contact."
        case .unsupportedKey: "This account key could not be used. Try the Web Vault on the same server."
        case .unsupportedItem: "This item could not be safely read. Try the Web Vault."
        case .passwordIncorrect: "The master password is incorrect."
        case .serverRejected: "The server rejected or did not confirm the action. Emergency access may be disabled. Refresh before trying again."
        case .unavailable: "It is not clear whether the server applied the action. Check your connection and refresh before trying again."
        case .invalidResponse: "The server sent an unexpected response. Refresh first or try the Web Vault."
        }
    }

    private func statusTitle(_ status: EmergencyAccessStatus) -> String {
        switch status {
        case .invited: "Invited"
        case .accepted: "Accepted — Awaiting Confirmation"
        case .confirmed: "Confirmed"
        case .recoveryInitiated: "Access Request Pending"
        case .recoveryApproved: "Access Approved"
        case .unknown(let value): "Unknown Status (\(value))"
        }
    }

    private func typeTitle(_ type: EmergencyAccessType) -> String {
        switch type {
        case .view: "Read Only"
        case .takeover: "Account Takeover"
        case .unknown(let value): "Unknown Access Type (\(value))"
        }
    }

    private func itemTypeTitle(_ type: CipherType) -> String {
        switch type {
        case .login: "Login"
        case .secureNote: "Secure Note"
        case .card: "Card"
        case .identity: "Identity"
        case .sshKey: "SSH Key"
        case .unknown: "Unknown Item Type"
        }
    }

    private func actionTitle(_ action: EmergencyAccessAction, direction: EmergencyAccessDirection) -> String {
        switch action {
        case .reinvite: "Resend Invitation"
        case .request: "Request Access"
        case .approve: "Approve Now"
        case .reject: "Reject Access"
        case .revoke: direction == .trusted ? "Revoke Grant" : "Remove This Grant"
        }
    }

    private func actionRole(_ action: EmergencyAccessAction) -> ButtonRole? {
        action == .revoke || action == .reject ? .destructive : nil
    }

    private func actionMessage(_ review: ActionReview) -> String {
        let email = review.contact.email
        switch review.action {
        case .reinvite: return "Invite \(email) again? The server decides whether to send email."
        case .request: return "Request read-only access to the personal vault of \(email)? The server wait period is \(review.contact.waitTimeDays) days."
        case .approve: return "Approve access for \(email) without waiting? They can read your personal vault immediately. Anything they have already seen cannot be taken back."
        case .reject: return "Reject this request from \(email)? The contact can request access again. Anything already seen cannot be taken back."
        case .revoke:
            return review.contact.direction == .trusted
                ? "Revoke emergency access for \(email)? Anything they have already seen cannot be taken back."
                : "Remove emergency access granted by \(email)? You will need a new invitation to regain access."
        }
    }
}

private struct EmergencyAccessFieldRow: View {
    let field: EmergencyAccessItemDetails.Field
    @State private var revealed = false

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Text(verbatim: field.label)
                Spacer()
                Button(revealed ? "Hide" : "Show", systemImage: revealed ? "eye.slash" : "eye") { revealed.toggle() }
                    .buttonStyle(.borderless)
            }
            if revealed {
                Text(verbatim: field.value).monospaced().privacySensitive()
            }
        }
    }
}
