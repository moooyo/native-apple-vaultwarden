import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import Generators

@available(iOS 27.0, *)
struct CodesView: View {
    @State private var model: VaultListModel
    let vault: VaultService
    let onAdd: () -> Void

    @State private var toastMessage: String?
    @State private var toastTask: Task<Void, Never>?

    init(model: VaultListModel, vault: VaultService, onAdd: @escaping () -> Void) {
        _model = State(initialValue: model)
        self.vault = vault
        self.onAdd = onAdd
    }

    private var codeItems: [PlaintextCipher] {
        model.items.filter { $0.openVaultTOTPConfiguration != nil }
    }

    var body: some View {
        ScrollView {
            if codeItems.isEmpty, !model.isLoading {
                ContentUnavailableView(
                    "暂无验证码",
                    systemImage: "clock.badge.questionmark",
                    description: Text("为登录条目设置验证器密钥后，验证码会显示在这里。")
                )
                .padding(.top, 100)
            } else {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    OpenVaultCard(padding: 0) {
                        VStack(spacing: 0) {
                            ForEach(Array(codeItems.enumerated()), id: \.element.openVaultID) { index, cipher in
                                NavigationLink {
                                    ItemDetailView(model: ItemDetailModel(cipher: cipher), vault: vault) {
                                        Task { await model.load() }
                                    }
                                } label: {
                                    VaultItemRow(cipher: cipher, date: context.date, showsFavorite: false)
                                        .padding(.horizontal, Spacing.lg)
                                }
                                .buttonStyle(.plain)
                                .contextMenu {
                                    Button {
                                        copyCode(for: cipher, at: context.date)
                                    } label: {
                                        Label("复制验证码", systemImage: "doc.on.doc")
                                    }
                                }
                                .swipeActions(edge: .leading, allowsFullSwipe: true) {
                                    Button {
                                        copyCode(for: cipher, at: context.date)
                                    } label: {
                                        Label("复制", systemImage: "doc.on.doc")
                                    }
                                    .tint(Palette.teal)
                                }

                                if index < codeItems.count - 1 {
                                    Divider().padding(.leading, 60)
                                }
                            }
                        }
                    }
                    .swipeActionsContainer()
                    .padding(.horizontal, Spacing.lg)
                }
            }
        }
        .background(Palette.groupedBackground)
        .scrollEdgeEffectStyle(.soft, for: .all)
        .navigationTitle("验证码")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button(action: onAdd) { Image(systemName: "plus") }
                    .accessibilityLabel("新建含验证码的条目")
            }
        }
        .refreshable { await model.refresh() }
        .overlay { if model.isLoading, model.items.isEmpty { ProgressView() } }
        .copyToast(toastMessage)
        .onDisappear { toastTask?.cancel() }
    }

    private func copyCode(for cipher: PlaintextCipher, at date: Date) {
        guard let configuration = cipher.openVaultTOTPConfiguration else { return }
        Clipboard.copy(TOTP.code(for: configuration, at: date))
        showToast("已拷贝验证码")
    }

    private func showToast(_ message: String) {
        toastTask?.cancel()
        toastMessage = message
        toastTask = Task {
            try? await Task.sleep(for: .seconds(1.6))
            guard !Task.isCancelled else { return }
            toastMessage = nil
        }
    }
}

@available(iOS 27.0, *)
struct PadCodeDetailView: View {
    let cipher: PlaintextCipher
    @State private var toastMessage: String?
    @State private var toastTask: Task<Void, Never>?

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            ScrollView {
                VStack(spacing: Spacing.lg) {
                    BrandBadge(cipher.openVaultName, diameter: 60)
                    Text(cipher.openVaultName)
                        .font(.title2.bold())

                    if let configuration = cipher.openVaultTOTPConfiguration {
                        let raw = TOTP.code(for: configuration, at: context.date)
                        let formatted = OTPRingMath.formatCode(raw)
                        let seconds = TOTP.secondsRemaining(for: configuration, at: context.date)
                        let progress = OTPRingMath.progress(secondsRemaining: seconds,
                                                           period: configuration.period)

                        OpenVaultCard(cornerRadius: CornerRadius.iPadCard, padding: Spacing.xl) {
                            HStack(spacing: Spacing.lg) {
                                Text(formatted)
                                    .font(.system(size: 44, weight: .medium, design: .monospaced))
                                    .monospacedDigit()
                                    .minimumScaleFactor(0.6)
                                    .privacySensitive()
                                Spacer()
                                CountdownRing(progress: progress, size: 34, lineWidth: 3.2)
                            }
                        }

                        OpenVaultCard(cornerRadius: CornerRadius.iPadCard, padding: 0) {
                            VStack(spacing: 0) {
                                detailRow("账户", value: cipher.openVaultSubtitle ?? "—")
                                Divider().padding(.leading, Spacing.lg)
                                detailRow("网站", value: cipher.login?.uris.first?.uri ?? "—")
                            }
                        }

                        Button {
                            Clipboard.copy(raw)
                            showToast("已拷贝验证码")
                        } label: {
                            Label("拷贝验证码", systemImage: "doc.on.doc")
                                .font(.headline)
                                .frame(maxWidth: .infinity, minHeight: 50)
                        }
                        .buttonStyle(.borderedProminent)
                    }
                }
                .padding(Spacing.xl)
            }
        }
        .background(Palette.groupedBackground)
        .copyToast(toastMessage)
        .onDisappear { toastTask?.cancel() }
    }

    private func detailRow(_ label: String, value: String) -> some View {
        HStack {
            Text(label).foregroundStyle(Palette.secondaryText)
            Spacer()
            Text(value).lineLimit(1).truncationMode(.middle)
        }
        .padding(.horizontal, Spacing.lg)
        .frame(minHeight: 52)
    }

    private func showToast(_ message: String) {
        toastTask?.cancel()
        toastMessage = message
        toastTask = Task {
            try? await Task.sleep(for: .seconds(1.6))
            guard !Task.isCancelled else { return }
            toastMessage = nil
        }
    }
}
