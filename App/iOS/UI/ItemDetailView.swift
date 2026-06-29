// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// ItemDetailView — read view for one decrypted cipher. Uses `SecureRevealView` for the
// password (controlled reveal bound to the model's `revealPassword`), `OTPRingView` for
// a live TOTP, and copy buttons that route through the iOS `Clipboard`.
//
// The TOTP code/seconds are recomputed each tick by re-reading the model's computed
// `totpCode` / `totpSecondsRemaining`; a `TimelineView`-less timer drives the refresh.

import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import Generators

@available(iOS 26.0, *)
public struct ItemDetailView: View {
    @State private var model: ItemDetailModel
    private let vault: VaultService
    /// Called after a successful edit so the list can reload.
    private let onChanged: () -> Void

    @State private var showingEdit = false
    /// A 1 Hz tick so the live TOTP code + countdown refresh.
    @State private var tick = Date()

    private let totpTimer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    public init(model: ItemDetailModel, vault: VaultService, onChanged: @escaping () -> Void) {
        _model = State(initialValue: model)
        self.vault = vault
        self.onChanged = onChanged
    }

    private var cipher: PlaintextCipher { model.cipher }

    public var body: some View {
        List {
            if let login = cipher.login {
                loginSection(login)
            }

            if let notes = cipher.notes, !notes.isEmpty {
                Section("Notes") {
                    Text(notes)
                        .font(Typography.rowSubtitle)
                        .textSelection(.enabled)
                }
            }

            if !(cipher.login?.uris ?? []).isEmpty {
                Section("URIs") {
                    ForEach(cipher.login?.uris ?? [], id: \.uri) { uri in
                        CopyRow(title: uri.uri, systemImage: "link") {
                            Clipboard.copy(uri.uri, expiresAfter: nil)
                        }
                    }
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
                ItemEditView(vault: vault, existing: cipher) { _ in
                    showingEdit = false
                    onChanged()
                }
            }
        }
        .onReceive(totpTimer) { tick = $0 }
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
