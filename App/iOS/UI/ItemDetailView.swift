// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// ItemDetailView — read view for one decrypted cipher. Uses `SecureRevealView` for the
// password (controlled reveal bound to the model's `revealPassword`), `OTPRingView` for
// a live TOTP, and copy buttons that route through the iOS `Clipboard`.
//
// The TOTP code/seconds are recomputed each tick by re-reading the model's computed
// `totpCode` / `totpSecondsRemaining`; a `TimelineView`-less timer drives the refresh.

import SwiftUI
import Combine
import UIShared
import DesignSystem
import VaultRepository
import VaultModels
import Generators

@available(iOS 26.0, *)
public struct ItemDetailView: View {
    @State private var model: ItemDetailModel
    private let sourceCipher: PlaintextCipher
    private let vault: VaultService
    /// Called after a successful edit so the list can reload.
    private let onChanged: () -> Void

    @State private var showingEdit = false
    @State private var revealCardNumber = false
    @State private var revealCardCode = false
    @State private var revealSSN = false
    @State private var revealPassportNumber = false
    @State private var revealLicenseNumber = false
    @State private var revealPrivateKey = false
    /// A 1 Hz tick so the live TOTP code + countdown refresh.
    @State private var tick = Date()

    private let totpTimer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    public init(model: ItemDetailModel, vault: VaultService, onChanged: @escaping () -> Void) {
        _model = State(initialValue: model)
        self.sourceCipher = model.cipher
        self.vault = vault
        self.onChanged = onChanged
    }

    private var cipher: PlaintextCipher { model.cipher }

    public var body: some View {
        List {
            typeSpecificSections

            if let notes = cipher.notes, !notes.isEmpty {
                Section("Notes") {
                    Text(notes)
                        .font(Typography.rowSubtitle)
                        .textSelection(.enabled)
                }
            }

        }
        .listStyle(.insetGrouped)
        .navigationTitle(cipher.name.isEmpty ? "Item" : cipher.name)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Edit") { showingEdit = true }
            }
        }
        .sheet(isPresented: $showingEdit) {
            NavigationStack {
                ItemEditView(vault: vault, existing: cipher) { id in
                    showingEdit = false
                    Task {
                        if let updated = try? await vault.cipher(id: id) {
                            model.replaceCipher(updated)
                        }
                        onChanged()
                    }
                }
            }
        }
        .onReceive(totpTimer) { tick = $0 }
        .onChange(of: sourceCipher) { _, updated in
            model.replaceCipher(updated)
        }
    }

    @ViewBuilder
    private var typeSpecificSections: some View {
        switch CipherType(rawValue: cipher.type) {
        case .login:
            if let login = cipher.login {
                loginSection(login)
                if !login.uris.isEmpty {
                    Section("URIs") {
                        ForEach(login.uris, id: \.uri) { uri in
                            CopyRow(title: uri.uri, systemImage: "link") {
                                Clipboard.copy(uri.uri, expiresAfter: nil)
                            }
                        }
                    }
                }
            }
        case .secureNote:
            EmptyView()
        case .card:
            if let card = cipher.card { cardSection(card) }
        case .identity:
            if let identity = cipher.identity { identitySections(identity) }
        case .sshKey:
            if let sshKey = cipher.sshKey { sshKeySection(sshKey) }
        case .unknown:
            EmptyView()
        }
    }

    @ViewBuilder
    private func loginSection(_ login: PlaintextCipher.Login) -> some View {
        Section("Login") {
            if let username = login.username, !username.isEmpty {
                CopyRow(title: username, subtitle: "Username", systemImage: "person") {
                    if let value = model.copyUsername() { Clipboard.copy(value, expiresAfter: nil) }
                }
            }

            if let password = login.password, !password.isEmpty {
                // Controlled reveal — bound to the model so lock/timeout can re-hide it.
                SecureRevealView(
                    title: "Password",
                    value: password,
                    isRevealed: $model.revealPassword,
                    isMonospaced: true
                ) {
                    if let value = model.copyPassword() { Clipboard.copy(value) }
                }
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
            }

            if model.hasTOTP, let config = model.totpConfiguration {
                HStack {
                    // `tick` participates so the ring/code refresh each second.
                    OTPRingView(configuration: config, at: tick)
                    Spacer()
                    Button {
                        if let value = model.copyTOTP() { Clipboard.copy(value) }
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .buttonStyle(.glass)
                    .accessibilityLabel("Copy one-time code")
                }
            }
        }
    }

    @ViewBuilder
    private func cardSection(_ card: PlaintextCipher.Card) -> some View {
        Section("Card") {
            if let value = card.cardholderName.nonEmpty {
                CopyRow(title: value, subtitle: "Cardholder", systemImage: "person") {
                    Clipboard.copy(value, expiresAfter: nil)
                }
            }
            if let value = card.brand.nonEmpty {
                CopyRow(title: value, subtitle: "Brand", systemImage: "creditcard") {
                    Clipboard.copy(value, expiresAfter: nil)
                }
            }
            if let value = card.number.nonEmpty {
                sensitiveRow(title: "Card number", value: value,
                             isRevealed: $revealCardNumber)
            }
            if let value = card.expMonth.nonEmpty {
                CopyRow(title: value, subtitle: "Expiration month", systemImage: "calendar") {
                    Clipboard.copy(value, expiresAfter: nil)
                }
            }
            if let value = card.expYear.nonEmpty {
                CopyRow(title: value, subtitle: "Expiration year", systemImage: "calendar") {
                    Clipboard.copy(value, expiresAfter: nil)
                }
            }
            if let value = card.code.nonEmpty {
                sensitiveRow(title: "Security code (CVV)", value: value,
                             isRevealed: $revealCardCode)
            }
        }
    }

    @ViewBuilder
    private func identitySections(_ identity: PlaintextCipher.Identity) -> some View {
        Section("Identity") {
            copyRow(identity.title, label: "Title", systemImage: "person.text.rectangle")
            copyRow(identity.firstName, label: "First name", systemImage: "person")
            copyRow(identity.middleName, label: "Middle name", systemImage: "person")
            copyRow(identity.lastName, label: "Last name", systemImage: "person")
            copyRow(identity.username, label: "Username", systemImage: "at")
            copyRow(identity.company, label: "Company", systemImage: "building.2")
            copyRow(identity.email, label: "Email", systemImage: "envelope")
            copyRow(identity.phone, label: "Phone", systemImage: "phone")
        }
        Section("Address") {
            copyRow(identity.address1, label: "Address line 1", systemImage: "house")
            copyRow(identity.address2, label: "Address line 2", systemImage: "house")
            copyRow(identity.address3, label: "Address line 3", systemImage: "house")
            copyRow(identity.city, label: "City", systemImage: "mappin")
            copyRow(identity.state, label: "State / Province", systemImage: "map")
            copyRow(identity.postalCode, label: "Postal code", systemImage: "number")
            copyRow(identity.country, label: "Country", systemImage: "globe")
        }
        Section("Identification") {
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

    @ViewBuilder
    private func sshKeySection(_ sshKey: PlaintextCipher.SshKey) -> some View {
        Section("SSH Key") {
            if let value = sshKey.privateKey.nonEmpty {
                sensitiveRow(title: "Private key", value: value,
                             isRevealed: $revealPrivateKey)
            }
            copyRow(sshKey.publicKey, label: "Public key", systemImage: "key.horizontal")
            copyRow(sshKey.keyFingerprint, label: "Fingerprint", systemImage: "number")
        }
    }

    @ViewBuilder
    private func copyRow(_ value: String?, label: String, systemImage: String) -> some View {
        if let value = value.nonEmpty {
            CopyRow(title: value, subtitle: label, systemImage: systemImage) {
                Clipboard.copy(value, expiresAfter: nil)
            }
        }
    }

    private func sensitiveRow(title: String, value: String,
                              isRevealed: Binding<Bool>) -> some View {
        SecureRevealView(title: title, value: value, isRevealed: isRevealed) {
            Clipboard.copy(value)
        }
        .listRowInsets(EdgeInsets())
        .listRowBackground(Color.clear)
    }
}

private extension Optional where Wrapped == String {
    var nonEmpty: String? {
        guard let self, !self.isEmpty else { return nil }
        return self
    }
}

// MARK: - A tappable copy row

@available(iOS 26.0, *)
private struct CopyRow: View {
    let title: String
    var subtitle: String? = nil
    let systemImage: String
    let onCopy: () -> Void

    var body: some View {
        HStack(spacing: Spacing.md) {
            Image(systemName: systemImage)
                .foregroundStyle(Palette.accent)
                .frame(width: 24)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                if let subtitle {
                    Text(subtitle)
                        .font(Typography.caption)
                        .foregroundStyle(Palette.secondaryText)
                }
                Text(title)
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
            .accessibilityLabel("Copy \(subtitle ?? title)")
        }
    }
}
