import SwiftUI
import DesignSystem
import VaultRepository

enum VaultSortOrder: String, CaseIterable, Identifiable {
    case name, modified, type

    var id: Self { self }

    var title: String {
        switch self {
        case .name: "名称"
        case .modified: "修改日期"
        case .type: "类型"
        }
    }

    func sorted(_ items: [PlaintextCipher]) -> [PlaintextCipher] {
        items.sorted { first, second in
            switch self {
            case .modified:
                let firstDate = first.revisionDate ?? .distantPast
                let secondDate = second.revisionDate ?? .distantPast
                if firstDate != secondDate { return firstDate > secondDate }
            case .type:
                let comparison = first.openVaultKindLabel.localizedStandardCompare(second.openVaultKindLabel)
                if comparison != .orderedSame { return comparison == .orderedAscending }
            case .name: break
            }
            let comparison = first.openVaultName.localizedStandardCompare(second.openVaultName)
            return comparison == .orderedSame ? first.openVaultID < second.openVaultID : comparison == .orderedAscending
        }
    }
}

struct VaultSortMenu: View {
    @Binding var selection: VaultSortOrder
    var symbol = "line.3.horizontal.decrease"

    var body: some View {
        Menu {
            Picker("排序方式", selection: $selection) {
                ForEach(VaultSortOrder.allCases) { sort in Text(sort.title).tag(sort) }
            }
            .pickerStyle(.inline)
        } label: {
            Label("排序与筛选", systemImage: symbol)
        }
        .accessibilityIdentifier("vault.sort")
    }
}

struct VaultFilterChips: View {
    @Binding var selection: VaultWorkspaceSection
    let items: [PlaintextCipher]
    var wraps = false
    var search = false
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.colorSchemeContrast) private var contrast

    private var selectedForeground: Color { colorScheme == .dark && contrast == .increased ? .black : .white }

    private var choices: [VaultWorkspaceSection] {
        if search { return VaultWorkspaceSection.itemTypes }
        if wraps { return [.all, .favorites, .logins, .cards, .identities, .secureNotes, .sshKeys] }
        return [.all] + VaultWorkspaceSection.itemTypes
    }

    var body: some View {
        if wraps {
            VaultChipLayout { chips() }
        } else {
            ScrollView(.horizontal) {
                HStack(spacing: Spacing.sm) { chips(wrapping: false) }
            }
            .scrollIndicators(.hidden)
        }
    }

    private func chips(wrapping: Bool = true) -> some View {
        ForEach(choices) { choice in
            let selected = selection == choice
            let title = choice == .all ? "全部" : choice.title
            Button {
                selection = search && selected ? .all : choice
            } label: {
                HStack(spacing: Spacing.xs) {
                    if selected, differentiateWithoutColor {
                        Image(systemName: "checkmark").accessibilityHidden(true)
                    } else if search {
                        Image(systemName: choice.systemImage)
                            .foregroundStyle(selected ? selectedForeground : Palette.accent)
                            .accessibilityHidden(true)
                    }
                    Text(title).fontWeight(.medium).fixedSize(horizontal: false, vertical: true)
                    if !search {
                        Text(items.count(where: { $0.isIncluded(in: choice) }), format: .number)
                            .monospacedDigit()
                            .foregroundStyle(selected ? selectedForeground : Palette.secondaryText)
                    }
                }
                .font(.subheadline)
                .fixedSize(horizontal: !wrapping, vertical: false)
                .padding(.horizontal, 14)
                .padding(.vertical, Spacing.xs)
                .frame(minHeight: 36)
                .foregroundStyle(selected ? selectedForeground : Palette.primaryText)
                .background(selected ? Color.accentColor : Palette.controlFill, in: Capsule())
                .overlay {
                    if contrast == .increased { Capsule().strokeBorder(Palette.separator, lineWidth: 1) }
                }
                .frame(minHeight: 44)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityAddTraits(selected ? .isSelected : [])
            .accessibilityIdentifier("vault.filter.\(choice.rawValue)")
        }
    }
}

private struct VaultChipLayout: Layout {
    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        arrange(width: proposal.width, subviews: subviews).size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let frames = arrange(width: bounds.width, subviews: subviews).frames
        for (view, frame) in zip(subviews, frames) {
            view.place(at: CGPoint(x: bounds.minX + frame.minX, y: bounds.minY + frame.minY),
                       anchor: .topLeading, proposal: ProposedViewSize(frame.size))
        }
    }

    private func arrange(width: CGFloat?, subviews: Subviews) -> (frames: [CGRect], size: CGSize) {
        var frames: [CGRect] = []
        var next = CGPoint.zero
        var rowHeight: CGFloat = 0
        var usedWidth: CGFloat = 0
        for view in subviews {
            let ideal = view.sizeThatFits(.unspecified)
            let size = width.map { view.sizeThatFits(ProposedViewSize(width: min(ideal.width, $0), height: nil)) } ?? ideal
            if let width, next.x > 0, next.x + size.width > width {
                next = CGPoint(x: 0, y: next.y + rowHeight + Spacing.xs)
                rowHeight = 0
            }
            frames.append(CGRect(origin: next, size: size))
            usedWidth = max(usedWidth, next.x + size.width)
            rowHeight = max(rowHeight, size.height)
            next.x += size.width + Spacing.sm
        }
        return (frames, CGSize(width: usedWidth, height: next.y + rowHeight))
    }
}
