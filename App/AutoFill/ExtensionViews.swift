// Xcode-only target. Not part of the SPM build.
//
// ExtensionViews — the small SwiftUI surfaces the AutoFill extension shows. These are the only
// UI in the extension (it links DesignSystem for tokens but NOT the heavy UI-* packages), so
// they are deliberately minimal: an unlock prompt, a credential picker, and a config screen.

import SwiftUI
import DesignSystem
import VaultReader

// MARK: - Unlock

/// The biometric-unlock prompt shown before vending a credential.
struct ExtensionUnlockView: View {
    let onUnlock: () -> Void
    let onCancel: () -> Void

    @State private var didTrigger = false

    var body: some View {
        VStack(spacing: Spacing.lg) {
            Image(systemName: "lock.shield")
                .font(.system(size: 44, weight: .semibold))
                .foregroundStyle(Palette.accent)

            Text("Unlock Tessera")
                .font(Typography.sectionTitle)
            Text("Use Face ID or Touch ID to fill your credential.")
                .font(Typography.rowSubtitle)
                .foregroundStyle(Palette.secondaryText)
                .multilineTextAlignment(.center)

            Button("Unlock", action: onUnlock)
                .buttonStyle(.borderedProminent)

            Button("Cancel", role: .cancel, action: onCancel)
                .buttonStyle(.borderless)
        }
        .padding(Spacing.xl)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Palette.groupedBackground)
        .onAppear {
            // Trigger the biometric prompt immediately so the user doesn't need a second tap;
            // the explicit button remains for retry / VoiceOver.
            guard !didTrigger else { return }
            didTrigger = true
            onUnlock()
        }
    }
}

// MARK: - Credential list (picker)

/// A bounded manual picker backed by non-secret metadata from `VaultReader`. Its async loader
/// performs biometric unlock before reading the encrypted cache; passwords, TOTP seeds, and
/// passkey private keys are decrypted only after the user selects one row.
@MainActor
struct ExtensionCredentialListView: View {
    let serviceIdentifiers: [String]
    let loadCandidates: () async throws -> [CredentialCandidate]
    let onSelect: (CredentialCandidate) -> Void
    let onCancel: () -> Void

    @State private var candidates: [CredentialCandidate] = []
    @State private var isLoading = true
    @State private var didStartLoading = false
    @State private var isCompleting = false
    @State private var loadFailed = false

    var body: some View {
        VStack(spacing: Spacing.lg) {
            Image(systemName: "key.horizontal")
                .font(.system(size: 40, weight: .semibold))
                .foregroundStyle(Palette.accent)

            Text("Tessera")
                .font(Typography.sectionTitle)

            Text(prompt)
                .font(Typography.rowSubtitle)
                .foregroundStyle(Palette.secondaryText)
                .multilineTextAlignment(.center)

            Group {
                if isLoading {
                    ProgressView("Unlocking vault…")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if loadFailed {
                    ContentUnavailableView {
                        Label("Couldn't Open Vault", systemImage: "lock.trianglebadge.exclamationmark")
                    } description: {
                        Text("Unlock Tessera to load credentials from the encrypted cache.")
                    } actions: {
                        Button("Try Again") {
                            Task { await reload() }
                        }
                    }
                } else if candidates.isEmpty {
                    ContentUnavailableView(
                        "No Matching Credentials",
                        systemImage: "key.slash",
                        description: Text("Open Tessera and sync this account, then try again.")
                    )
                } else {
                    ScrollView {
                        LazyVStack(spacing: Spacing.sm) {
                            ForEach(candidates) { candidate in
                                Button {
                                    guard !isCompleting else { return }
                                    isCompleting = true
                                    onSelect(candidate)
                                } label: {
                                    candidateRow(candidate)
                                }
                                .buttonStyle(.plain)
                                .disabled(isCompleting)
                            }
                        }
                        .padding(.horizontal, Spacing.xs)
                    }
                    .frame(maxHeight: 360)
                }
            }

            Button("Cancel", role: .cancel, action: onCancel)
                .buttonStyle(.borderless)
                .disabled(isCompleting)
        }
        .padding(Spacing.xl)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Palette.groupedBackground)
        .task {
            guard !didStartLoading else { return }
            didStartLoading = true
            await reload()
        }
    }

    private var prompt: String {
        guard let first = serviceIdentifiers.first, !first.isEmpty else {
            return "Choose a credential to fill."
        }
        return "Choose a credential for \(first)."
    }

    @ViewBuilder
    private func candidateRow(_ candidate: CredentialCandidate) -> some View {
        HStack(spacing: Spacing.md) {
            Image(systemName: iconName(for: candidate.kind))
                .font(.title3)
                .foregroundStyle(Palette.accent)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: Spacing.xs) {
                Text(candidate.name)
                    .font(Typography.rowTitle)
                    .foregroundStyle(Palette.primaryText)
                    .lineLimit(1)
                if !candidate.user.isEmpty {
                    Text(candidate.user)
                        .font(Typography.rowSubtitle)
                        .foregroundStyle(Palette.secondaryText)
                        .lineLimit(1)
                }
                if !candidate.serviceIdentifier.isEmpty {
                    Text(candidate.serviceIdentifier)
                        .font(.caption)
                        .foregroundStyle(Palette.secondaryText)
                        .lineLimit(1)
                }
            }

            Spacer(minLength: Spacing.sm)

            Text(kindLabel(for: candidate.kind))
                .font(.caption)
                .foregroundStyle(Palette.secondaryText)
        }
        .padding(Spacing.md)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            Palette.contentBackground,
            in: RoundedRectangle(cornerRadius: CornerRadius.card)
        )
        .contentShape(Rectangle())
    }

    private func reload() async {
        isLoading = true
        loadFailed = false
        isCompleting = false
        do {
            candidates = try await loadCandidates()
            isLoading = false
        } catch {
            candidates = []
            isLoading = false
            loadFailed = true
        }
    }

    private func iconName(for kind: CredentialCandidate.Kind) -> String {
        switch kind {
        case .password: "person.badge.key"
        case .oneTimeCode: "timer"
        case .passkey: "person.crop.circle.badge.checkmark"
        }
    }

    private func kindLabel(for kind: CredentialCandidate.Kind) -> String {
        switch kind {
        case .password: "Password"
        case .oneTimeCode: "Code"
        case .passkey: "Passkey"
        }
    }
}

// MARK: - Configuration

/// The onboarding screen shown when the user enables the provider in Settings → Passwords.
struct ConfigurationView: View {
    let onDone: () -> Void

    var body: some View {
        VStack(spacing: Spacing.lg) {
            Image(systemName: "checkmark.shield")
                .font(.system(size: 48, weight: .semibold))
                .foregroundStyle(Palette.success)

            Text("Tessera AutoFill is ready")
                .font(Typography.sectionTitle)
            Text("Open the Tessera app and sign in to sync your vault, then your logins and passkeys will appear here.")
                .font(Typography.rowSubtitle)
                .foregroundStyle(Palette.secondaryText)
                .multilineTextAlignment(.center)

            Button("Done", action: onDone)
                .buttonStyle(.borderedProminent)
        }
        .padding(Spacing.xl)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Palette.groupedBackground)
    }
}
