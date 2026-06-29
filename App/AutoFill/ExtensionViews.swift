// Xcode-only target. Not part of the SPM build.
//
// ExtensionViews — the small SwiftUI surfaces the AutoFill extension shows. These are the only
// UI in the extension (it links DesignSystem for tokens but NOT the heavy UI-* packages), so
// they are deliberately minimal: an unlock prompt, a credential picker, and a config screen.

import SwiftUI
import DesignSystem

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

/// A minimal picker. Real entries are surfaced by the system from `ASCredentialIdentityStore`;
/// this fallback list lets the user trigger unlock + selection inside the extension UI when the
/// system hands off a service-identifier query. (M1: shows the queried domains; selection wires
/// the recordID through once the system match is resolved.)
struct ExtensionCredentialListView: View {
    let serviceIdentifiers: [String]
    let onSelect: (String) -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(spacing: Spacing.lg) {
            Image(systemName: "key.horizontal")
                .font(.system(size: 40, weight: .semibold))
                .foregroundStyle(Palette.accent)

            Text("Tessera")
                .font(Typography.sectionTitle)

            if let first = serviceIdentifiers.first {
                Text("Fill a saved login for \(first)?")
                    .font(Typography.rowSubtitle)
                    .foregroundStyle(Palette.secondaryText)
                    .multilineTextAlignment(.center)
            } else {
                Text("Pick a saved login from the list above, then unlock to fill it.")
                    .font(Typography.rowSubtitle)
                    .foregroundStyle(Palette.secondaryText)
                    .multilineTextAlignment(.center)
            }

            Button("Cancel", role: .cancel, action: onCancel)
                .buttonStyle(.borderless)
        }
        .padding(Spacing.xl)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Palette.groupedBackground)
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
