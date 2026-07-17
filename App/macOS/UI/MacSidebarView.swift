import SwiftUI
import UIShared
import DesignSystem

@available(macOS 27.0, *)
struct MacSidebarView: View {
    @Binding var selection: MacDestination
    @Binding var searchText: String
    let searchFocus: FocusState<Bool>.Binding
    let counts: MacSidebarCounts
    let syncModel: SyncStatusModel
    let onSync: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            searchField

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    sidebarRow(.all)
                    sidebarRow(.favorites)
                    sidebarRow(.authenticator)
                    sidebarRow(.security)

                    sectionLabel("类型")
                    sidebarRow(.login)
                    sidebarRow(.card)
                    sidebarRow(.identity)
                    sidebarRow(.secureNote)

                    sectionLabel("工具")
                    sidebarRow(.generator)
                    sidebarRow(.send)
                }
                .padding(.horizontal, 10)
                .padding(.bottom, 12)
            }
            .scrollIndicators(.hidden)

            accountFooter
        }
        .padding(.top, 44)
        .background {
            ZStack {
                Color.clear
                    .glassStyle(in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(Color(red: 46 / 255, green: 50 / 255, blue: 62 / 255).opacity(0.36))
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .stroke(.white.opacity(0.10), lineWidth: 0.5)
            }
        }
        .padding(10)
        .background(MacOpenVaultStyle.window)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("OpenVault 侧栏")
    }

    private var searchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(MacOpenVaultStyle.secondary)
            TextField("搜索", text: $searchText)
                .textFieldStyle(.plain)
                .font(.system(size: 12.5))
                .focused(searchFocus)
                .accessibilityLabel("搜索保险库")
            Text("⌘K")
                .font(.system(size: 10, weight: .medium, design: .rounded))
                .foregroundStyle(.white.opacity(0.32))
                .padding(.horizontal, 4)
                .padding(.vertical, 1)
                .overlay {
                    RoundedRectangle(cornerRadius: 4, style: .continuous)
                        .stroke(.white.opacity(0.14), lineWidth: 0.5)
                }
        }
        .padding(.horizontal, 9)
        .frame(height: 30)
        .background {
            Capsule().fill(.white.opacity(0.07))
        }
        .overlay { Capsule().stroke(.white.opacity(0.09), lineWidth: 0.5) }
        .padding(.horizontal, 10)
        .padding(.bottom, 12)
    }

    private func sectionLabel(_ title: String) -> some View {
        Text(title)
            .font(.system(size: 10.5, weight: .bold))
            .foregroundStyle(.white.opacity(0.40))
            .textCase(.uppercase)
            .tracking(0.3)
            .padding(.horizontal, 8)
            .padding(.top, 11)
            .padding(.bottom, 3)
    }

    private func sidebarRow(_ destination: MacDestination) -> some View {
        Button {
            withAnimation(.snappy(duration: 0.22)) { selection = destination }
        } label: {
            HStack(spacing: 8) {
                Image(systemName: destination.systemImage)
                    .font(.system(size: 12, weight: .medium))
                    .symbolRenderingMode(.monochrome)
                    .foregroundStyle(selection == destination ? Color(red: 121 / 255, green: 186 / 255, blue: 1) : .white.opacity(0.56))
                    .frame(width: 14)

                Text(destination.title)
                    .font(.system(size: 13, weight: selection == destination ? .semibold : .regular))
                    .foregroundStyle(selection == destination ? .white : .white.opacity(0.86))
                    .lineLimit(1)

                Spacer(minLength: 4)

                if let count = counts.value(for: destination) {
                    Text(count, format: .number)
                        .font(.system(size: 11.5))
                        .monospacedDigit()
                        .foregroundStyle(.white.opacity(selection == destination ? 0.58 : 0.40))
                }
            }
            .padding(.horizontal, 8)
            .frame(height: 30)
            .contentShape(Rectangle())
            .background {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(selection == destination ? .white.opacity(0.14) : .clear)
            }
        }
        .buttonStyle(.plain)
        .accessibilityValue(selection == destination ? "已选择" : "")
    }

    private var accountFooter: some View {
        VStack(spacing: 0) {
            Divider().overlay(.white.opacity(0.08))
            HStack(spacing: 9) {
                OpenVaultMark(size: 28)
                VStack(alignment: .leading, spacing: 1) {
                    Text("OpenVault")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(.white.opacity(0.92))
                    syncLabel
                }
                Spacer(minLength: 4)
                Button {
                    selection = .settings
                } label: {
                    Image(systemName: "gearshape")
                        .font(.system(size: 12, weight: .medium))
                        .frame(width: 26, height: 26)
                }
                .buttonStyle(.glass)
                .help("设置")
            }
            .padding(.horizontal, 8)
            .padding(.top, 9)
            .padding(.bottom, 2)
        }
        .padding(.horizontal, 10)
    }

    @ViewBuilder
    private var syncLabel: some View {
        if syncModel.isSyncing {
            Text("正在同步…")
                .foregroundStyle(.white.opacity(0.46))
        } else if syncModel.errorMessage != nil {
            Button("同步失败 · 重试", action: onSync)
                .buttonStyle(.plain)
                .foregroundStyle(Color.orange)
        } else if let last = syncModel.lastSync {
            Button(action: onSync) {
                Text("已同步 · \(last.formatted(.relative(presentation: .named)))")
            }
            .buttonStyle(.plain)
            .foregroundStyle(.white.opacity(0.42))
        } else {
            Button("尚未同步 · 立即同步", action: onSync)
                .buttonStyle(.plain)
                .foregroundStyle(.white.opacity(0.42))
        }
    }
}
