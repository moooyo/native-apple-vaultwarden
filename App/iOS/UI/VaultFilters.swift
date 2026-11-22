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

    var body: some View {
        Menu {
            Picker("排序方式", selection: $selection) {
                ForEach(VaultSortOrder.allCases) { sort in Text(sort.title).tag(sort) }
            }
            .pickerStyle(.inline)
        } label: {
            Label("排序与筛选", systemImage: "arrow.up.arrow.down")
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
            VaultChipLayout { chips }
        } else {
            ScrollView(.horizontal) {
                HStack(spacing: Spacing.sm) { chips }
            }
            .scrollIndicators(.hidden)
        }
    }

    private var chips: some View {
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
                    Text(title).fontWeight(.medium)
                    if !search {
                        Text(items.count(where: { $0.isIncluded(in: choice) }), format: .number)
                            .monospacedDigit()
                    }
                }
                .font(.subheadline)
                .fixedSize(horizontal: true, vertical: false)
                .padding(.horizontal, 14)
                .padding(.vertical, Spacing.xs)
                .frame(minHeight: 36)
                .foregroundStyle(selected ? selectedForeground : Palette.primaryText)
                .background(selected ? Color.accentColor : Palette.controlFill, in: Capsule())
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
        let points = arrange(width: bounds.width, subviews: subviews).points
        for (view, point) in zip(subviews, points) {
            view.place(at: CGPoint(x: bounds.minX + point.x, y: bounds.minY + point.y),
                       anchor: .topLeading, proposal: .unspecified)
        }
    }

    private func arrange(width: CGFloat?, subviews: Subviews) -> (points: [CGPoint], size: CGSize) {
        var points: [CGPoint] = []
        var next = CGPoint.zero
        var rowHeight: CGFloat = 0
        var usedWidth: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if let width, next.x > 0, next.x + size.width > width {
                next = CGPoint(x: 0, y: next.y + rowHeight + Spacing.xs)
                rowHeight = 0
            }
            points.append(next)
            usedWidth = max(usedWidth, next.x + size.width)
            rowHeight = max(rowHeight, size.height)
            next.x += size.width + Spacing.sm
        }
        return (points, CGSize(width: usedWidth, height: next.y + rowHeight))
    }
}
