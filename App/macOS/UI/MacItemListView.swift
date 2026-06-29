// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// MacItemListView — the middle column: the filtered list of ciphers. Selection is an
// item-id binding owned by `MacMainView` (drives the detail column). Rows stay on the
// opaque content layer.

import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels

@available(macOS 26.0, *)
struct MacItemListView: View {
    let items: [PlaintextCipher]
    let isLoading: Bool
    @Binding var selection: String?

    var body: some View {
        List(selection: $selection) {
            ForEach(items, id: \.id) { cipher in
                MacItemRow(cipher: cipher)
                    .tag(cipher.id ?? "")
            }
        }
        .overlay {
            if items.isEmpty && !isLoading {
                ContentUnavailableView("No Items", systemImage: "tray",
                                       description: Text("Nothing in this category yet."))
            }
        }
    }
}

@available(macOS 26.0, *)
private struct MacItemRow: View {
    let cipher: PlaintextCipher

    var body: some View {
        HStack(spacing: Spacing.md) {
            Image(systemName: iconName)
                .foregroundStyle(Palette.accent)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text(cipher.name.isEmpty ? "(No name)" : cipher.name)
                    .font(Typography.rowTitle)
                    .lineLimit(1)
                if let subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(Typography.caption)
                        .foregroundStyle(Palette.secondaryText)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: Spacing.sm)
            if cipher.favorite {
                Image(systemName: "star.fill")
                    .font(.caption)
                    .foregroundStyle(Palette.caution)
            }
        }
        .padding(.vertical, Spacing.xxs)
    }

    private var subtitle: String? { cipher.login?.username ?? cipher.notes }

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
