// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// MacItemEditView — create / edit a `PlaintextCipher` on macOS (logins + secure notes in
// M1). Presented as a sheet from `MacMainView`/`MacItemDetailView`; calls the
// `VaultService` CRUD directly and hands the saved id back via `onSaved`.

import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels

@available(macOS 26.0, *)
struct MacItemEditView: View {
    private let vault: VaultService
    private let existing: PlaintextCipher?
    private let onSaved: (String) -> Void

    @Environment(\.dismiss) private var dismiss

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

    init(vault: VaultService, existing: PlaintextCipher? = nil, onSaved: @escaping (String) -> Void) {
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

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    Picker("Type", selection: $type) {
                        Text("Login").tag(CipherType.login.rawValue)
                        Text("Secure Note").tag(CipherType.secureNote.rawValue)
                    }
                    TextField("Name", text: $name)
                    Toggle("Favorite", isOn: $favorite)
                }

                if isLogin {
                    Section("Login") {
                        TextField("Username", text: $username)
                        HStack {
                            Group {
                                if revealPassword {
                                    TextField("Password", text: $password).font(Typography.secretValue)
                                } else {
                                    SecureField("Password", text: $password)
                                }
                            }
                            Button {
                                revealPassword.toggle()
                            } label: {
                                Image(systemName: revealPassword ? "eye.slash" : "eye")
                            }
                            .buttonStyle(.borderless)
                            .accessibilityLabel(revealPassword ? "Hide password" : "Reveal password")
                        }
                        TextField("Authenticator key (TOTP)", text: $totp)
                        TextField("Website (URI)", text: $uri)
                    }
                }

                Section("Notes") {
                    TextField("Notes", text: $notes, axis: .vertical)
                        .lineLimit(3...8)
                }

                if let errorMessage {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(Palette.danger)
                        .font(Typography.rowSubtitle)
                }
            }
            .formStyle(.grouped)

            Divider()

            HStack {
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                if isSaving {
                    ProgressView().controlSize(.small)
                } else {
                    Button("Save") { save() }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                        .disabled(!canSave)
                }
            }
            .padding(Spacing.lg)
        }
        .frame(width: 440, height: 480)
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
        let login: PlaintextCipher.Login? = isLogin
            ? PlaintextCipher.Login(
                username: username.nilIfEmpty,
                password: password.nilIfEmpty,
                totp: totp.nilIfEmpty,
                uris: uri.nilIfEmpty.map { [PlaintextCipher.Uri(uri: $0)] } ?? [])
            : nil
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
        trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : self
    }
}
