import SwiftUI
import DesignSystem
import VaultRepository

@available(macOS 27.0, *)
struct MacItemListView: View {
    enum SortOrder: String, CaseIterable {
        case name = "名称"
        case favorite = "置顶优先"
    }

    let title: String
    let items: [PlaintextCipher]
    let isLoading: Bool
    let errorMessage: String?
    @Binding var selection: String?
    let onNewItem: () -> Void

    @State private var sortOrder: SortOrder = .name

    private var sortedItems: [PlaintextCipher] {
        items.sorted { lhs, rhs in
            if sortOrder == .favorite, lhs.favorite != rhs.favorite { return lhs.favorite }
            return lhs.name.localizedStandardCompare(rhs.name) == .orderedAscending
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(.black.opacity(0.4))

            ZStack {
                ScrollView {
                    LazyVStack(spacing: 1) {
                        ForEach(sortedItems, id: \.macStableID) { cipher in
                            MacItemRow(cipher: cipher, isSelected: selection == cipher.macStableID) {
                                selection = cipher.macStableID
                            }
                        }
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 6)
                }
                .scrollIndicators(.automatic)

                stateOverlay
            }
        }
        .background(MacOpenVaultStyle.list)
    }

    private var header: some View {
        HStack(spacing: 9) {
            HStack(spacing: 5) {
                Button(action: {}) {
                    Image(systemName: "chevron.left")
                }
                .disabled(true)
                Button(action: {}) {
                    Image(systemName: "chevron.right")
                }
                .disabled(true)
            }
            .buttonStyle(.borderless)
            .font(.system(size: 11, weight: .semibold))

            Text(title)
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(.white)
                .lineLimit(1)

            Spacer(minLength: 4)

            Menu {
                Picker("排序", selection: $sortOrder) {
                    ForEach(SortOrder.allCases, id: \.self) { order in
                        Text(order.rawValue).tag(order)
                    }
                }
            } label: {
                Image(systemName: "line.3.horizontal.decrease")
                    .frame(width: 27, height: 27)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .glassStyle(in: Circle())
            .help("排序")

            Button(action: onNewItem) {
                Image(systemName: "plus")
                    .font(.system(size: 12, weight: .semibold))
                    .frame(width: 27, height: 27)
            }
            .buttonStyle(.glassProminent)
            .help("新建条目")
        }
        .padding(.leading, 12)
        .padding(.trailing, 10)
        .frame(height: 50)
    }

    @ViewBuilder
    private var stateOverlay: some View {
        if isLoading && items.isEmpty {
            ProgressView("正在载入保险库…")
                .controlSize(.small)
                .foregroundStyle(MacOpenVaultStyle.secondary)
        } else if let errorMessage, items.isEmpty {
            ContentUnavailableView("无法载入保险库", systemImage: "exclamationmark.triangle",
                                   description: Text(errorMessage))
        } else if items.isEmpty {
            ContentUnavailableView("没有条目", systemImage: "tray",
                                   description: Text("此分类中暂时没有内容。"))
        }
    }
}

@available(macOS 27.0, *)
private struct MacItemRow: View {
    let cipher: PlaintextCipher
    let isSelected: Bool
    let action: () -> Void

    @State private var isHovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                BrandBadge(cipher.name, diameter: 30)
                VStack(alignment: .leading, spacing: 1) {
                    Text(cipher.name.nilIfBlank ?? "未命名条目")
                        .font(.system(size: 13.5, weight: .semibold))
                        .foregroundStyle(isSelected ? .white : .white.opacity(0.92))
                        .lineLimit(1)
                    if let subtitle = cipher.macSubtitle {
                        Text(subtitle)
                            .font(.system(size: 11.5))
                            .foregroundStyle(isSelected ? .white.opacity(0.76) : .white.opacity(0.45))
                            .lineLimit(1)
                    }
                }
                Spacer(minLength: 4)
                if cipher.favorite {
                    Image(systemName: "star.fill")
                        .font(.system(size: 10))
                        .foregroundStyle(isSelected ? .white.opacity(0.9) : Color.yellow)
                }
            }
            .padding(.horizontal, 9)
            .frame(minHeight: 44)
            .contentShape(Rectangle())
            .background {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(backgroundColor)
            }
        }
        .buttonStyle(.plain)
        .onHover { isHovering = $0 }
        .accessibilityLabel(cipher.name.nilIfBlank ?? "未命名条目")
        .accessibilityValue(isSelected ? "已选择" : (cipher.macSubtitle ?? ""))
    }

    private var backgroundColor: Color {
        if isSelected { return MacOpenVaultStyle.selected }
        if isHovering { return .white.opacity(0.06) }
        return .clear
    }
}
