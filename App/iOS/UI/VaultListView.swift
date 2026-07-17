import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels

@available(iOS 27.0, *)
public struct VaultListView: View {
    @State private var model: VaultListModel
    @State private var operationError: String?
    private let vault: VaultService
    private let onAdd: () -> Void
    private let onOpenCodes: () -> Void
    private let onOpenSettings: () -> Void

    public init(model: VaultListModel, vault: VaultService,
                onAdd: @escaping () -> Void = {},
                onOpenCodes: @escaping () -> Void = {},
                onOpenSettings: @escaping () -> Void = {}) {
        _model = State(initialValue: model)
        self.vault = vault
        self.onAdd = onAdd
        self.onOpenCodes = onOpenCodes
        self.onOpenSettings = onOpenSettings
    }

    private var loginCount: Int {
        model.items.count { CipherType(rawValue: $0.type) == .login }
    }

    private var codeCount: Int {
        model.items.count { $0.openVaultTOTPConfiguration != nil }
    }

    private var favorites: [PlaintextCipher] {
        model.items.filter(\.favorite)
    }

    public var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: Spacing.lg) {
                if let message = model.errorMessage {
                    errorBanner(message)
                }

                dashboard

                if !favorites.isEmpty {
                    OpenVaultSectionTitle("置顶")
                    VaultRowsCard(items: favorites, vault: vault,
                                  onChanged: reload, onDelete: delete)
                        .padding(.horizontal, Spacing.lg)
                }

                OpenVaultSectionTitle("全部条目")
                if model.items.isEmpty, !model.isLoading {
                    OpenVaultCard {
                        ContentUnavailableView(
                            "保险库为空",
                            systemImage: "tray",
                            description: Text("轻点右上角的加号创建第一个条目。")
                        )
                        .frame(maxWidth: .infinity)
                    }
                    .padding(.horizontal, Spacing.lg)
                } else {
                    VaultRowsCard(items: model.items, vault: vault,
                                  onChanged: reload, onDelete: delete)
                        .padding(.horizontal, Spacing.lg)
                }

                if model.isLoading {
                    ProgressView().frame(maxWidth: .infinity).padding()
                }
            }
            .padding(.vertical, Spacing.sm)
        }
        .background(Palette.groupedBackground)
        .scrollEdgeEffectStyle(.soft, for: .all)
        .refreshable { await model.refresh() }
        .navigationTitle("保险库")
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                Button(action: onAdd) {
                    Image(systemName: "plus")
                }
                .accessibilityLabel("新建条目")

                Button(action: onOpenSettings) {
                    Text("O")
                        .font(.subheadline.weight(.semibold))
                        .frame(width: 22, height: 22)
                }
                .accessibilityLabel("打开设置")
            }
        }
        .task { if model.items.isEmpty { await model.load() } }
        .alert("无法删除条目", isPresented: hasOperationError) {
            Button("好", role: .cancel) { operationError = nil }
        } message: {
            Text(operationError ?? "请稍后再试。")
        }
    }

    private var dashboard: some View {
        LazyVGrid(columns: [GridItem(.flexible(), spacing: Spacing.md),
                            GridItem(.flexible())], spacing: Spacing.md) {
            DashboardStatTile(title: "登录项", value: loginCount,
                              systemImage: "key.fill", tint: Palette.accent)
            DashboardStatTile(title: "验证码", value: codeCount,
                              systemImage: "clock.fill", tint: Palette.teal,
                              action: onOpenCodes)
            DashboardStatTile(title: "置顶", value: favorites.count,
                              systemImage: "star.fill", tint: Palette.warning)
            DashboardStatTile(title: "全部条目", value: model.items.count,
                              systemImage: "square.grid.2x2.fill", tint: Palette.indigo)
        }
        .padding(.horizontal, Spacing.lg)
    }

    private func errorBanner(_ message: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle.fill")
            .font(.subheadline)
            .foregroundStyle(Palette.danger)
            .padding(Spacing.md)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Palette.danger.opacity(0.1),
                        in: RoundedRectangle(cornerRadius: CornerRadius.md, style: .continuous))
            .padding(.horizontal, Spacing.lg)
    }

    private func reload() {
        Task { await model.load() }
    }

    private func delete(_ cipher: PlaintextCipher) {
        guard let id = cipher.id else { return }
        Task {
            do {
                try await vault.deleteCipher(id: id)
                await model.load()
            } catch {
                operationError = "删除失败，条目未被更改。"
            }
        }
    }

    private var hasOperationError: Binding<Bool> {
        Binding(get: { operationError != nil }, set: { if !$0 { operationError = nil } })
    }
}

@available(iOS 27.0, *)
struct VaultSearchView: View {
    @State private var model: VaultListModel
    @State private var operationError: String?
    let vault: VaultService
    let onAdd: () -> Void

    init(model: VaultListModel, vault: VaultService, onAdd: @escaping () -> Void) {
        _model = State(initialValue: model)
        self.vault = vault
        self.onAdd = onAdd
    }

    var body: some View {
        ScrollView {
            if model.items.isEmpty, !model.isLoading {
                ContentUnavailableView(
                    model.query.isEmpty ? "搜索保险库" : "没有结果",
                    systemImage: "magnifyingglass",
                    description: Text(model.query.isEmpty
                                      ? "输入名称、用户名或网站。"
                                      : "没有条目与“\(model.query)”匹配。")
                )
                .padding(.top, 100)
            } else {
                VaultRowsCard(items: model.items, vault: vault,
                              onChanged: { Task { await model.search() } },
                              onDelete: delete)
                    .padding(Spacing.lg)
            }
        }
        .background(Palette.groupedBackground)
        .navigationTitle("搜索")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button(action: onAdd) { Image(systemName: "plus") }
                    .accessibilityLabel("新建条目")
            }
        }
        .overlay { if model.isLoading { ProgressView() } }
        .alert("无法删除条目", isPresented: hasOperationError) {
            Button("好", role: .cancel) { operationError = nil }
        } message: {
            Text(operationError ?? "请稍后再试。")
        }
    }

    private func delete(_ cipher: PlaintextCipher) {
        guard let id = cipher.id else { return }
        Task {
            do {
                try await vault.deleteCipher(id: id)
                await model.search()
            } catch {
                operationError = "删除失败，条目未被更改。"
            }
        }
    }

    private var hasOperationError: Binding<Bool> {
        Binding(get: { operationError != nil }, set: { if !$0 { operationError = nil } })
    }
}
