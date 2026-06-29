// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// VaultListView — an opaque `List` of `ConcentricRectangleCard` rows from
// `VaultListModel`. Pull-to-refresh runs `model.refresh()` (sync + reload); swipe
// actions delete; `.scrollEdgeEffectStyle` keeps rows readable as they scroll under
// the floating glass tab bar.
//
// Liquid Glass note: list rows stay on the OPAQUE content layer (the card is a solid
// fill). Glass lives only in the surrounding tab/nav chrome.

import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels

@available(iOS 26.0, *)
public struct VaultListView: View {
    @State private var model: VaultListModel
    private let vault: VaultService

    public init(model: VaultListModel, vault: VaultService) {
        _model = State(initialValue: model)
        self.vault = vault
    }

    public var body: some View {
        List {
            if let message = model.errorMessage {
                Section {
                    Label(message, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(Palette.danger)
                        .font(Typography.rowSubtitle)
                }
                .listRowBackground(Color.clear)
            }

            ForEach(model.items, id: \.id) { cipher in
                NavigationLink {
                    ItemDetailView(model: ItemDetailModel(cipher: cipher), vault: vault) {
                        Task { await model.load() }
                    }
                } label: {
                    ConcentricRectangleCard {
                        VaultRowContent(cipher: cipher)
                    }
                }
                .listRowInsets(EdgeInsets(top: Spacing.xs, leading: Spacing.lg,
                                          bottom: Spacing.xs, trailing: Spacing.lg))
                .listRowSeparator(.hidden)
                .listRowBackground(Color.clear)
                .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                    Button(role: .destructive) {
                        delete(cipher)
                    } label: {
                        Label("Delete", systemImage: "trash")
                    }
                }
                .swipeActions(edge: .leading) {
                    if let username = cipher.login?.username, !username.isEmpty {
                        Button {
                            Clipboard.copy(username)
                        } label: {
                            Label("Copy User", systemImage: "person")
                        }
                        .tint(Palette.accent)
                    }
                }
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .background(Palette.groupedBackground)
        // Soften content as it passes under the floating glass bars.
        .scrollEdgeEffectStyle(.soft, for: .all)
        .overlay {
            if model.items.isEmpty && !model.isLoading {
                ContentUnavailableView(
                    model.query.isEmpty ? "No Items" : "No Results",
                    systemImage: model.query.isEmpty ? "tray" : "magnifyingglass",
                    description: Text(model.query.isEmpty
                                      ? "Add a login with the + button."
                                      : "No items match “\(model.query)”.")
                )
            }
        }
        .refreshable { await model.refresh() }
        .navigationTitle("Vault")
        .task { if model.items.isEmpty { await model.load() } }
    }

    private func delete(_ cipher: PlaintextCipher) {
        guard let id = cipher.id else { return }
        Task {
            try? await vault.deleteCipher(id: id)
            await model.load()
        }
    }
}

// MARK: - Row content

@available(iOS 26.0, *)
private struct VaultRowContent: View {
    let cipher: PlaintextCipher

    var body: some View {
        HStack(spacing: Spacing.md) {
            Image(systemName: iconName)
                .font(.title3)
                .foregroundStyle(Palette.accent)
                .frame(width: 28)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text(cipher.name.isEmpty ? "(No name)" : cipher.name)
                    .font(Typography.rowTitle)
                    .foregroundStyle(Palette.primaryText)
                    .lineLimit(1)
                if let subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(Typography.rowSubtitle)
                        .foregroundStyle(Palette.secondaryText)
                        .lineLimit(1)
                }
            }

            Spacer(minLength: Spacing.sm)

            if cipher.favorite {
                Image(systemName: "star.fill")
                    .font(.caption)
                    .foregroundStyle(Palette.caution)
                    .accessibilityLabel("Favorite")
            }
        }
    }

    private var subtitle: String? {
        cipher.login?.username ?? cipher.notes
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
