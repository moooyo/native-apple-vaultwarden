// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// ItemEditView — create or edit a `PlaintextCipher` (M1 covers logins + secure notes).
// Calls `VaultService.createCipher` / `updateCipher` directly; on success it hands the
// (possibly new) id back via `onSaved` so the list can reload.
//
// The password field is masked unless the user reveals it, and is entered via a system
// `SecureField` — never rendered on clear glass.

import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels

@available(iOS 26.0, *)
public struct ItemEditView: View {
    private let vault: VaultService
    private let existing: PlaintextCipher?
    /// Called with the saved cipher's id on success.
    private let onSaved: (String) -> Void

    @Environment(\.dismiss) private var dismiss

    // Editable fields.
    @State private var type: Int
    @State private var name: String
    @State private var username: String
    @State private var password: String
    @State private var totp: String
    @State private var uri: String
    @State private var notes: String
    @State private var favorite: Bool

    @State private var revealPassword = false
    @State private var isSaving = false
    @State private var errorMessage: String?

    public init(vault: VaultService, existing: PlaintextCipher? = nil,
                onSaved: @escaping (String) -> Void) {
        self.vault = vault
        self.existing = existing
        self.onSaved = onSaved
        _type = State(initialValue: existing?.type ?? CipherType.login.rawValue)
        _name = State(initialValue: existing?.name ?? "")
        _username = State(initialValue: existing?.login?.username ?? "")
        _password = State(initialValue: existing?.login?.password ?? "")
        _totp = State(initialValue: existing?.login?.totp ?? "")
        _uri = State(initialValue: existing?.login?.uris.first?.uri ?? "")
        _notes = State(initialValue: existing?.notes ?? "")
        _favorite = State(initialValue: existing?.favorite ?? false)
    }

    private var isLogin: Bool { type == CipherType.login.rawValue }
    private var canSave: Bool { !name.trimmingCharacters(in: .whitespaces).isEmpty && !isSaving }

    public var body: some View {
        Form {
            Section {
                Picker("Type", selection: $type) {
                    Text("Login").tag(CipherType.login.rawValue)
                    Text("Secure Note").tag(CipherType.secureNote.rawValue)
                }
                TextField("Name", text: $name)
                    .textInputAutocapitalization(.words)
                Toggle("Favorite", isOn: $favorite)
            }

            if isLogin {
                Section("Login") {
                    TextField("Username", text: $username)
                        .textContentType(.username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()

                    HStack {
                        Group {
                            if revealPassword {
                                TextField("Password", text: $password)
                                    .font(Typography.secretValue)
                            } else {
                                SecureField("Password", text: $password)
                            }
                        }
                        .textContentType(.password)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()

                        Button {
                            revealPassword.toggle()
                        } label: {
                            Image(systemName: revealPassword ? "eye.slash" : "eye")
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel(revealPassword ? "Hide password" : "Reveal password")
                    }

                    TextField("Authenticator key (TOTP)", text: $totp)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()

                    TextField("Website (URI)", text: $uri)
                        .textContentType(.URL)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
            }

            Section("Notes") {
                TextField("Notes", text: $notes, axis: .vertical)
                    .lineLimit(3...8)
            }

            if let errorMessage {
                Section {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(Palette.danger)
                        .font(Typography.rowSubtitle)
                }
            }
        }
        .navigationTitle(existing == nil ? "New Item" : "Edit Item")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                if isSaving {
                    ProgressView()
                } else {
                    Button("Save") { save() }.disabled(!canSave)
                }
            }
        }
    }

    private func save() {
        isSaving = true
        errorMessage = nil
        let cipher = buildCipher()
        Task {
            do {
                if let id = existing?.id {
                    try await vault.updateCipher(id: id, cipher)
                    onSaved(id)
                } else {
                    let newID = try await vault.createCipher(cipher)
                    onSaved(newID)
                }
                dismiss()
            } catch {
                errorMessage = "Could not save the item. Please try again."
            }
            isSaving = false
        }
    }

    private func buildCipher() -> PlaintextCipher {
        let login: PlaintextCipher.Login?
        if isLogin {
            login = PlaintextCipher.Login(
                username: username.nilIfEmpty,
                password: password.nilIfEmpty,
                totp: totp.nilIfEmpty,
                uris: uri.nilIfEmpty.map { [PlaintextCipher.Uri(uri: $0)] } ?? []
            )
        } else {
            login = nil
        }
        return PlaintextCipher(
            id: existing?.id,
            type: type,
            name: name.trimmingCharacters(in: .whitespaces),
            notes: notes.nilIfEmpty,
            folderID: existing?.folderID,
            favorite: favorite,
            reprompt: existing?.reprompt ?? 0,
            login: login
        )
    }
}

private extension String {
    var nilIfEmpty: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : self
    }
}
