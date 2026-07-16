// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// MacItemDetailView — the trailing column: a decrypted cipher's fields, with an
// `.inspector(isPresented:)` panel for metadata / password history. The detail hero uses
// `.backgroundExtensionEffect()` so the header tint extends under the sidebar/inspector.
//
// Reveal/TOTP/copy reuse the same UIShared `ItemDetailModel` and DesignSystem components
// as iOS; copy routes through `MacClipboard` (NSPasteboard) in this macOS-only file.

import SwiftUI
import Combine
import UIShared
import DesignSystem
import VaultRepository
import VaultModels
import Generators

@available(macOS 26.0, *)
struct MacItemDetailView: View {
    @State private var model: ItemDetailModel
    private let sourceCipher: PlaintextCipher
    private let vault: VaultService
    private let onChanged: () -> Void

    @State private var showInspector = false
    @State private var showingEdit = false
    @State private var showingDeleteConfirm = false
    @State private var revealCardNumber = false
    @State private var revealCardCode = false
    @State private var revealSSN = false
    @State private var revealPassportNumber = false
    @State private var revealLicenseNumber = false
    @State private var revealPrivateKey = false
    @State private var tick = Date()

    private let totpTimer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    init(cipher: PlaintextCipher, vault: VaultService, onChanged: @escaping () -> Void) {
        _model = State(initialValue: ItemDetailModel(cipher: cipher))
        self.sourceCipher = cipher
        self.vault = vault
        self.onChanged = onChanged
    }

    private var cipher: PlaintextCipher { model.cipher }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.lg) {
                hero
                typeSpecificCards

                if let notes = cipher.notes, !notes.isEmpty {
                    card(title: "Notes") {
                        Text(notes)
                            .font(Typography.rowSubtitle)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
            .padding(Spacing.xl)
        }
        .navigationTitle(cipher.name.isEmpty ? "Item" : cipher.name)
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button { showingEdit = true } label: {
                    Label("Edit", systemImage: "pencil")
                }
                Button(role: .destructive) { showingDeleteConfirm = true } label: {
                    Label("Delete", systemImage: "trash")
                }
            }
            ToolbarSpacer(.fixed)
            ToolbarItemGroup(placement: .primaryAction) {
                Button { showInspector.toggle() } label: {
                    Label("Info", systemImage: "info.circle")
                }
            }
        }
        .inspector(isPresented: $showInspector) {
            MacItemInspector(cipher: cipher)
                .inspectorColumnWidth(min: 240, ideal: 280, max: 360)
        }
        .sheet(isPresented: $showingEdit) {
            MacItemEditView(vault: vault, existing: cipher) { id in
                showingEdit = false
                Task {
                    if let updated = try? await vault.cipher(id: id) {
                        model.replaceCipher(updated)
                    }
                    onChanged()
                }
            }
        }
        .onReceive(totpTimer) { tick = $0 }
        .onChange(of: sourceCipher) { _, updated in
            model.replaceCipher(updated)
        }
        .confirmationDialog(
            "Delete this item?",
            isPresented: $showingDeleteConfirm,
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                Task {
                    guard let id = cipher.id else { return }
                    do {
                        try await vault.deleteCipher(id: id)
                        onChanged()
                    } catch {}
                }
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    // MARK: - Hero (background extension effect)

    private var hero: some View {
        HStack(spacing: Spacing.lg) {
            Image(systemName: iconName)
                .font(.system(size: 36, weight: .semibold))
                .foregroundStyle(Palette.accent)
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text(cipher.name.isEmpty ? "(No name)" : cipher.name)
                    .font(Typography.sectionTitle)
                if let detailSubtitle {
                    Text(detailSubtitle)
                        .font(Typography.rowSubtitle)
                        .foregroundStyle(Palette.secondaryText)
                }
            }
            Spacer()
        }
        .padding(Spacing.lg)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Palette.contentBackground.opacity(0.6))
        // Mirror+blur the hero content under the adjacent sidebar/inspector columns.
        .backgroundExtensionEffect()
        .clipShape(RoundedRectangle(cornerRadius: CornerRadius.card, style: .continuous))
    }

    private var detailSubtitle: String? {
        switch CipherType(rawValue: cipher.type) {
        case .login:
            return cipher.login?.username.nonEmpty
        case .secureNote:
            return nil
        case .card:
            return cipher.card?.cardholderName.nonEmpty ?? cipher.card?.brand.nonEmpty
        case .identity:
            let parts = [cipher.identity?.firstName, cipher.identity?.middleName,
                         cipher.identity?.lastName].compactMap { $0.nonEmpty }
            return parts.isEmpty ? cipher.identity?.email.nonEmpty : parts.joined(separator: " ")
        case .sshKey:
            return cipher.sshKey?.keyFingerprint.nonEmpty
        case .unknown:
            return nil
        }
    }

    @ViewBuilder
    private var typeSpecificCards: some View {
        switch CipherType(rawValue: cipher.type) {
        case .login:
            if let login = cipher.login { loginCard(login) }
        case .secureNote:
            EmptyView()
        case .card:
            if let cardValue = cipher.card { paymentCard(cardValue) }
        case .identity:
            if let identity = cipher.identity { identityCards(identity) }
        case .sshKey:
            if let sshKey = cipher.sshKey { sshKeyCard(sshKey) }
        case .unknown:
            EmptyView()
        }
    }

    // MARK: - Login card

    @ViewBuilder
    private func loginCard(_ login: PlaintextCipher.Login) -> some View {
        card(title: "Login") {
            VStack(alignment: .leading, spacing: Spacing.md) {
                if let username = login.username, !username.isEmpty {
                    MacCopyRow(label: "Username", value: username) {
                        MacClipboard.copy(username)
                    }
                }

                if let password = login.password, !password.isEmpty {
                    SecureRevealView(
                        title: "Password",
                        value: password,
                        isRevealed: $model.revealPassword,
                        isMonospaced: true
                    ) {
                        if let value = model.copyPassword() { MacClipboard.copy(value) }
                    }
                }

                if model.hasTOTP, let config = model.totpConfiguration {
                    HStack {
                        OTPRingView(configuration: config, at: tick)
                        Spacer()
                        Button {
                            if let value = model.copyTOTP() { MacClipboard.copy(value) }
                        } label: {
                            Image(systemName: "doc.on.doc")
                        }
                        .buttonStyle(.glass)
                        .accessibilityLabel("Copy one-time code")
                    }
                }

                ForEach(login.uris, id: \.uri) { uri in
                    MacCopyRow(label: "Website", value: uri.uri) {
                        MacClipboard.copy(uri.uri)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func paymentCard(_ paymentCard: PlaintextCipher.Card) -> some View {
        card(title: "Card") {
            VStack(alignment: .leading, spacing: Spacing.md) {
                copyRow(paymentCard.cardholderName, label: "Cardholder")
                copyRow(paymentCard.brand, label: "Brand")
                if let value = paymentCard.number.nonEmpty {
                    sensitiveRow(title: "Card number", value: value,
                                 isRevealed: $revealCardNumber)
                }
                copyRow(paymentCard.expMonth, label: "Expiration month")
                copyRow(paymentCard.expYear, label: "Expiration year")
                if let value = paymentCard.code.nonEmpty {
                    sensitiveRow(title: "Security code (CVV)", value: value,
                                 isRevealed: $revealCardCode)
                }
            }
        }
    }

    @ViewBuilder
    private func identityCards(_ identity: PlaintextCipher.Identity) -> some View {
        card(title: "Identity") {
            VStack(alignment: .leading, spacing: Spacing.md) {
                copyRow(identity.title, label: "Title")
                copyRow(identity.firstName, label: "First name")
                copyRow(identity.middleName, label: "Middle name")
                copyRow(identity.lastName, label: "Last name")
                copyRow(identity.username, label: "Username")
                copyRow(identity.company, label: "Company")
                copyRow(identity.email, label: "Email")
                copyRow(identity.phone, label: "Phone")
            }
        }
        card(title: "Address") {
            VStack(alignment: .leading, spacing: Spacing.md) {
                copyRow(identity.address1, label: "Address line 1")
                copyRow(identity.address2, label: "Address line 2")
                copyRow(identity.address3, label: "Address line 3")
                copyRow(identity.city, label: "City")
                copyRow(identity.state, label: "State / Province")
                copyRow(identity.postalCode, label: "Postal code")
                copyRow(identity.country, label: "Country")
            }
        }
        card(title: "Identification") {
            VStack(alignment: .leading, spacing: Spacing.md) {
                if let value = identity.ssn.nonEmpty {
                    sensitiveRow(title: "Social Security number", value: value,
                                 isRevealed: $revealSSN)
                }
                if let value = identity.passportNumber.nonEmpty {
                    sensitiveRow(title: "Passport number", value: value,
                                 isRevealed: $revealPassportNumber)
                }
                if let value = identity.licenseNumber.nonEmpty {
                    sensitiveRow(title: "License number", value: value,
                                 isRevealed: $revealLicenseNumber)
                }
            }
        }
    }

    @ViewBuilder
    private func sshKeyCard(_ sshKey: PlaintextCipher.SshKey) -> some View {
        card(title: "SSH Key") {
            VStack(alignment: .leading, spacing: Spacing.md) {
                if let value = sshKey.privateKey.nonEmpty {
                    sensitiveRow(title: "Private key", value: value,
                                 isRevealed: $revealPrivateKey)
                }
                copyRow(sshKey.publicKey, label: "Public key")
                copyRow(sshKey.keyFingerprint, label: "Fingerprint")
            }
        }
    }

    @ViewBuilder
    private func copyRow(_ value: String?, label: String) -> some View {
        if let value = value.nonEmpty {
            MacCopyRow(label: label, value: value) {
                MacClipboard.copy(value)
            }
        }
    }

    private func sensitiveRow(title: String, value: String,
                              isRevealed: Binding<Bool>) -> some View {
        SecureRevealView(title: title, value: value, isRevealed: isRevealed) {
            MacClipboard.copy(value)
        }
    }

    // MARK: - Card container

    @ViewBuilder
    private func card<Content: View>(title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            Text(title)
                .font(Typography.caption)
                .foregroundStyle(Palette.secondaryText)
            ConcentricRectangleCard { content() }
        }
    }

    private var iconName: String {
        switch CipherType(rawValue: cipher.type) {
        case .login: return "person.crop.circle"
        case .secureNote: return "note.text"
        case .card: return "creditcard"
        case .identity: return "person.text.rectangle"
        case .sshKey: return "key.horizontal"
        case .unknown: return "doc"
        }
    }
}

private extension Optional where Wrapped == String {
    var nonEmpty: String? {
        guard let self, !self.isEmpty else { return nil }
        return self
    }
}

// MARK: - A non-sensitive copy row (username / website)

@available(macOS 26.0, *)
private struct MacCopyRow: View {
    let label: String
    let value: String
    let onCopy: () -> Void

    var body: some View {
        HStack(spacing: Spacing.md) {
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text(label)
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
                Text(value)
                    .font(Typography.rowTitle)
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: Spacing.sm)
            Button(action: onCopy) {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.glass)
            .accessibilityLabel("Copy \(label)")
        }
    }
}

// MARK: - Inspector (metadata / password history)

@available(macOS 26.0, *)
private struct MacItemInspector: View {
    let cipher: PlaintextCipher

    var body: some View {
        Form {
            Section("Metadata") {
                LabeledContent("Type", value: typeLabel)
                LabeledContent("Favorite", value: cipher.favorite ? "Yes" : "No")
                if let id = cipher.id {
                    LabeledContent("Item ID") {
                        Text(id).font(Typography.caption).textSelection(.enabled)
                            .lineLimit(1).truncationMode(.middle)
                    }
                }
                LabeledContent("Reprompt", value: cipher.reprompt == 0 ? "Off" : "On")
            }

            Section("Password History") {
                // M1 placeholder — the PlaintextCipher shape doesn't yet carry history;
                // password history lands in M2 (design spec §11).
                Text("No history available.")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
            }
        }
        .formStyle(.grouped)
    }

    private var typeLabel: String {
        switch CipherType(rawValue: cipher.type) {
        case .login: return "Login"
        case .secureNote: return "Secure Note"
        case .card: return "Card"
        case .identity: return "Identity"
        case .sshKey: return "SSH Key"
        case .unknown: return "Other"
        }
    }
}
