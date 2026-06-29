// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// MacItemDetailView — the trailing column: a decrypted cipher's fields, with an
// `.inspector(isPresented:)` panel for metadata / password history. The detail hero uses
// `.backgroundExtensionEffect()` so the header tint extends under the sidebar/inspector.
//
// Reveal/TOTP/copy reuse the same UIShared `ItemDetailModel` and DesignSystem components
// as iOS; copy routes through `MacClipboard` (NSPasteboard) in this macOS-only file.

import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels
import Generators

@available(macOS 26.0, *)
struct MacItemDetailView: View {
    @State private var model: ItemDetailModel
    private let vault: VaultService
    private let onChanged: () -> Void

    @State private var showInspector = false
    @State private var showingEdit = false
    @State private var tick = Date()

    private let totpTimer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    init(cipher: PlaintextCipher, vault: VaultService, onChanged: @escaping () -> Void) {
        _model = State(initialValue: ItemDetailModel(cipher: cipher))
        self.vault = vault
        self.onChanged = onChanged
    }

    private var cipher: PlaintextCipher { model.cipher }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.lg) {
                hero

                if let login = cipher.login {
                    loginCard(login)
                }

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
            MacItemEditView(vault: vault, existing: cipher) { _ in
                showingEdit = false
                onChanged()
            }
        }
        .onReceive(totpTimer) { tick = $0 }
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
                if let username = cipher.login?.username, !username.isEmpty {
                    Text(username)
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
