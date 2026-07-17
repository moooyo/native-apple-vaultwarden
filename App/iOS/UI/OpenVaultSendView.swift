import SwiftUI
import DesignSystem

@available(iOS 27.0, *)
struct OpenVaultSendView: View {
    private enum Filter: String, CaseIterable, Identifiable {
        case all = "全部"
        case text = "文本"
        case file = "文件"
        var id: String { rawValue }
    }

    @State private var filter: Filter = .all
    @State private var showingUnavailable = false

    var body: some View {
        ScrollView {
            VStack(spacing: Spacing.lg) {
                Picker("发送类型", selection: $filter) {
                    ForEach(Filter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .frame(maxWidth: 360)

                OpenVaultCard {
                    ContentUnavailableView(
                        "暂无发送项目",
                        systemImage: "paperplane",
                        description: Text("保险库同步与条目功能可正常使用；Bitwarden Send 服务尚未接入此客户端。")
                    )
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, Spacing.xl)
                }

                Label("发送内容需要端到端加密和可撤销链接支持。在后端能力完成前，这里不会显示虚构记录。",
                      systemImage: "lock.shield")
                    .font(.subheadline)
                    .foregroundStyle(Palette.secondaryText)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(Spacing.lg)
        }
        .background(Palette.groupedBackground)
        .navigationTitle("发送")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button { showingUnavailable = true } label: {
                    Image(systemName: "plus")
                }
                .accessibilityLabel("新建发送")
            }
        }
        .alert("Send 尚未可用", isPresented: $showingUnavailable) {
            Button("好", role: .cancel) {}
        } message: {
            Text("接入服务端 Send API 后即可在这里创建加密文本与文件分享。")
        }
    }
}
