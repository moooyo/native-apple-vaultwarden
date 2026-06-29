// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// MenuBarContent — the content view for a `MenuBarExtra` (the scene itself is declared in
// the App target later). Provides quick unlock, an inline search, and one-tap copy of a
// matching login's username/password.
//
// Security: the password is NEVER shown here — only copied (via NSPasteboard) on demand.
// The menu shows a locked state until the user unlocks.

import SwiftUI
import UIShared
import DesignSystem
import VaultRepository

@available(macOS 26.0, *)
public struct MenuBarContent: View {
    private let auth: AuthService
    private let vault: VaultService

    @State private var unlockModel: UnlockModel
    @State private var listModel: VaultListModel
    @State private var isUnlocked = false
    @State private var query = ""

    public init(auth: AuthService, vault: VaultService) {
        self.auth = auth
        self.vault = vault
        _unlockModel = State(initialValue: UnlockModel(auth: auth))
        _listModel = State(initialValue: VaultListModel(vault: vault))
    }

    /// Results limited to the search query, capped so the menu stays compact.
    private var results: [PlaintextCipher] {
        let trimmed = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !trimmed.isEmpty else { return Array(listModel.items.prefix(8)) }
        return listModel.items
            .filter { $0.name.lowercased().contains(trimmed)
                   || ($0.login?.username?.lowercased().contains(trimmed) ?? false) }
            .prefix(8)
            .map { $0 }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            if isUnlocked {
                unlockedContent
            } else {
                lockedContent
            }
        }
        .padding(Spacing.md)
        .frame(width: 320)
        .task {
            isUnlocked = await auth.isUnlocked()
            if isUnlocked { await listModel.load() }
        }
    }

    // MARK: - Locked

    private var lockedContent: some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            Label("Tessera is locked", systemImage: "lock.fill")
                .font(Typography.rowTitle)

            SecureField("Master password", text: $unlockModel.password)
                .textContentType(.password)
                .onSubmit { unlock() }

            if let message = unlockModel.errorMessage {
                Text(message)
                    .font(Typography.caption)
                    .foregroundStyle(Palette.danger)
            }

            HStack {
                Button("Touch ID") {
                    Task {
                        await unlockModel.unlockWithBiometrics()
                        await refreshUnlocked()
                    }
                }
                Spacer()
                Button("Unlock") { unlock() }
                    .buttonStyle(.borderedProminent)
                    .disabled(unlockModel.password.isEmpty)
            }
        }
    }

    // MARK: - Unlocked

    private var unlockedContent: some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            TextField("Search", text: $query)
                .textFieldStyle(.roundedBorder)

            if results.isEmpty {
                Text("No matches")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
            } else {
                ForEach(results, id: \.id) { cipher in
                    MenuResultRow(cipher: cipher)
                }
            }

            Divider()
            Button {
                Task { await auth.lock(); isUnlocked = false }
            } label: {
                Label("Lock", systemImage: "lock")
            }
            .buttonStyle(.borderless)
        }
    }

    private func unlock() {
        Task {
            await unlockModel.unlockWithPassword()
            await refreshUnlocked()
        }
    }

    private func refreshUnlocked() async {
        isUnlocked = await auth.isUnlocked()
        if isUnlocked { await listModel.load() }
    }
}

// MARK: - A single result row with copy actions

@available(macOS 26.0, *)
private struct MenuResultRow: View {
    let cipher: PlaintextCipher

    var body: some View {
        HStack(spacing: Spacing.sm) {
            VStack(alignment: .leading, spacing: 0) {
                Text(cipher.name.isEmpty ? "(No name)" : cipher.name)
                    .font(Typography.rowSubtitle)
                    .lineLimit(1)
                if let username = cipher.login?.username, !username.isEmpty {
                    Text(username)
                        .font(Typography.caption)
                        .foregroundStyle(Palette.secondaryText)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: Spacing.sm)

            if let username = cipher.login?.username, !username.isEmpty {
                Button {
                    MacClipboard.copy(username)
                } label: {
                    Image(systemName: "person")
                }
                .buttonStyle(.borderless)
                .help("Copy username")
            }
            if let password = cipher.login?.password, !password.isEmpty {
                Button {
                    MacClipboard.copy(password)
                } label: {
                    Image(systemName: "key")
                }
                .buttonStyle(.borderless)
                .help("Copy password")
            }
        }
    }
}
