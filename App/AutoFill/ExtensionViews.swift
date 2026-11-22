import SwiftUI
import DesignSystem
import VaultReader

struct ExtensionUnlockView: View {
    let onUnlock: () async -> Void
    let onCancel: () -> Void

    @State private var unlocking = false
    @State private var started = false

    var body: some View {
        VStack(spacing: Spacing.lg) {
            HStack {
                Spacer()
                ExtensionCloseButton(action: onCancel)
            }
            ScrollView {
                VStack(spacing: Spacing.lg) {
                    OpenVaultMark(size: 64)
                    Text("保险库已锁定")
                        .font(.title.bold())
                        .accessibilityAddTraits(.isHeader)
                    Button {
                        Task { await unlock() }
                    } label: {
                        HStack {
                            if unlocking { ProgressView().controlSize(.small) }
                            Text(unlocking ? "正在解锁…" : "使用生物识别解锁")
                        }
                        .font(.headline)
                        .frame(maxWidth: .infinity, minHeight: 44)
                    }
                    .vaultProminentButtonStyle()
                    .buttonBorderShape(.capsule)
                    .disabled(unlocking)
                }
                .frame(maxWidth: 320)
                .frame(maxWidth: .infinity)
                .padding(.vertical, Spacing.lg)
            }
            .scrollBounceBehavior(.basedOnSize)
        }
        .padding(Spacing.lg)
        .background(Palette.groupedBackground)
        .task {
            guard !started else { return }
            started = true
            await unlock()
        }
    }

    private func unlock() async {
        guard !unlocking else { return }
        unlocking = true
        await onUnlock()
        unlocking = false
    }
}

@MainActor
struct ExtensionCredentialListView: View {
    let serviceIdentifiers: [String]
    let loadCandidates: () async throws -> [CredentialCandidate]
    let searchCandidates: ((String) async throws -> [CredentialCandidate])?
    let onSelect: (CredentialCandidate) -> Void
    let onCancel: () -> Void

    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @FocusState private var queryFocused: Bool
    @State private var candidates: [CredentialCandidate] = []
    @State private var loadedRequest: Request?
    @State private var failedRequest: Request?
    @State private var isCompleting = false
    @State private var searching = false
    @State private var query = ""
    @State private var attempt = 0

    init(serviceIdentifiers: [String],
         loadCandidates: @escaping () async throws -> [CredentialCandidate],
         searchCandidates: ((String) async throws -> [CredentialCandidate])? = nil,
         onSelect: @escaping (CredentialCandidate) -> Void, onCancel: @escaping () -> Void) {
        self.serviceIdentifiers = serviceIdentifiers
        self.loadCandidates = loadCandidates
        self.searchCandidates = searchCandidates
        self.onSelect = onSelect
        self.onCancel = onCancel
    }

    private struct Request: Equatable {
        let query: String?
        let attempt: Int
    }

    private var request: Request {
        Request(query: searching ? query.trimmingCharacters(in: .whitespacesAndNewlines) : nil,
                attempt: attempt)
    }

    private var requestedHosts: [String] {
        serviceIdentifiers.compactMap { CredentialCandidate.displayHost(for: $0) }
    }

    private var visibleCandidates: [CredentialCandidate] {
        if searching { return candidates }
        let hosts = Set(requestedHosts)
        guard !hosts.isEmpty else { return candidates }
        return candidates.filter { candidate in
            candidate.kind == .passkey || candidate.displayHost.map(hosts.contains) == true
        }
    }

    private var prompt: String {
        if searching { return "搜索其他凭据" }
        return requestedHosts.first.map { "选择用于 \($0) 的凭据" } ?? "选择填充凭据"
    }

    var body: some View {
        let current = request
        VStack(spacing: 0) {
            HStack(alignment: .top, spacing: Spacing.md) {
                VStack(alignment: .leading, spacing: Spacing.sm) {
                    HStack(spacing: Spacing.sm) {
                        OpenVaultMark(size: 22)
                        Text("OpenVault")
                            .font(.footnote.weight(.semibold))
                            .foregroundStyle(.secondary)
                    }
                    Text(prompt)
                        .font(.title3.weight(.semibold))
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityAddTraits(.isHeader)
                }
                Spacer(minLength: Spacing.xs)
                ExtensionCloseButton(action: onCancel)
                    .disabled(isCompleting)
            }
            .padding(.horizontal, Spacing.lg)
            .padding(.vertical, Spacing.md)

            List {
                Section {
                    if failedRequest == current {
                        ContentUnavailableView {
                            Label("无法读取凭据", systemImage: "lock.trianglebadge.exclamationmark")
                        } description: {
                            Text("请确认 OpenVault 已登录、完成同步并启用了生物识别。")
                        } actions: {
                            Button("重试") { attempt += 1 }.buttonStyle(.bordered)
                        }
                    } else if loadedRequest != current {
                        ProgressView("正在读取凭据…")
                            .frame(maxWidth: .infinity, minHeight: 66)
                    } else {
                        let rows = visibleCandidates
                        let recentID = rows.filter { $0.recentUseRank != nil }.min {
                            ($0.recentUseRank ?? .max) < ($1.recentUseRank ?? .max)
                        }?.id
                        if rows.isEmpty {
                            Text(searching ? "没有找到凭据" : "没有匹配的凭据")
                                .foregroundStyle(.secondary)
                                .frame(minHeight: 52)
                        }
                        ForEach(rows) { candidate in credentialButton(candidate, recent: candidate.id == recentID) }
                        if !searching {
                            Button {
                                searching = true
                            } label: {
                                Label("搜索其他凭据", systemImage: "magnifyingglass")
                                    .frame(maxWidth: .infinity, minHeight: 52, alignment: .leading)
                                    .contentShape(Rectangle())
                            }
                            .accessibilityIdentifier("autofill.searchOther")
                        }
                    }
                }
                .listRowInsets(EdgeInsets(top: 0, leading: Spacing.lg, bottom: 0, trailing: Spacing.lg))
            }
            #if os(iOS)
            .listStyle(.insetGrouped)
            .contentMargins(.top, Spacing.xs, for: .scrollContent)
            #else
            .listStyle(.inset)
            #endif
            .scrollContentBackground(.hidden)
            .scrollDismissesKeyboard(.interactively)

            if searching { searchControls }
        }
        .frame(maxWidth: 540)
        .frame(maxWidth: .infinity)
        .background(Palette.groupedBackground)
        .task(id: current) { await load(current) }
        .onChange(of: searching) { _, active in queryFocused = active }
        .accessibilityAction(.escape) { if !isCompleting { onCancel() } }
    }

    private func credentialButton(_ candidate: CredentialCandidate, recent: Bool) -> some View {
        let kind = kindLabel(candidate.kind)
        let metadata = [candidate.user.isEmpty ? nil : candidate.name,
                        searching ? candidate.displayHost : nil, kind]
            .compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
        return Button {
            guard !isCompleting else { return }
            isCompleting = true
            onSelect(candidate)
        } label: {
            HStack(spacing: Spacing.md) {
                if candidate.kind == .passkey {
                    Image(systemName: "person.badge.key.fill")
                        .foregroundStyle(.tint)
                        .frame(width: 40, height: 40)
                        .background(Palette.controlFill, in: RoundedRectangle(cornerRadius: 10))
                        .accessibilityHidden(true)
                } else {
                    BrandBadge(candidate.name, diameter: 40)
                }
                VStack(alignment: .leading, spacing: Spacing.xs) {
                    Text(candidate.user.isEmpty ? candidate.name : candidate.user)
                        .font(.body.weight(.semibold))
                    Text(metadata).font(.subheadline).foregroundStyle(.secondary)
                    if recent && dynamicTypeSize.isAccessibilitySize { recentBadge }
                }
                .lineLimit(dynamicTypeSize.isAccessibilitySize ? nil : 2)
                Spacer(minLength: 0)
                if recent && !dynamicTypeSize.isAccessibilitySize { recentBadge }
            }
            .padding(.vertical, Spacing.sm)
            .frame(maxWidth: .infinity, minHeight: 66, alignment: .leading)
            .contentShape(Rectangle())
        }
        .disabled(isCompleting)
        .buttonStyle(.plain)
        .accessibilityLabel([candidate.user, candidate.name, candidate.displayHost ?? "", kind, recent ? "最近使用" : ""]
            .filter { !$0.isEmpty }.joined(separator: "，"))
        .accessibilityHint("填充此凭据")
    }

    private var recentBadge: some View {
        Text("最近使用")
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, Spacing.sm)
            .padding(.vertical, Spacing.xs)
            .background(Palette.controlFill, in: Capsule())
    }

    private var searchControls: some View {
        HStack(spacing: Spacing.sm) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary).accessibilityHidden(true)
            TextField("搜索名称、用户名或网站", text: $query)
                .textFieldStyle(.plain)
                .autocorrectionDisabled()
                #if os(iOS)
                .textInputAutocapitalization(.never)
                #endif
                .focused($queryFocused)
                .submitLabel(.search)
                .accessibilityIdentifier("autofill.query")
            if !query.isEmpty {
                Button("清除搜索", systemImage: "xmark.circle.fill") { query = "" }
                    .labelStyle(.iconOnly)
                    .foregroundStyle(.secondary)
                    .frame(minWidth: 44, minHeight: 44)
            }
            Button("取消") { query = ""; searching = false }
                .frame(minWidth: 44, minHeight: 44)
                .accessibilityIdentifier("autofill.endSearch")
        }
        .padding(.horizontal, Spacing.lg)
        .padding(.bottom, Spacing.xs)
    }

    private func load(_ request: Request) async {
        failedRequest = nil
        do {
            let results: [CredentialCandidate]
            if let query = request.query, let searchCandidates {
                if !query.isEmpty { try await Task.sleep(for: .milliseconds(180)) }
                results = try await searchCandidates(query)
            } else {
                let available = try await loadCandidates()
                results = available.filter { $0.matchesSearch(request.query ?? "") }
            }
            try Task.checkCancellation()
            candidates = results
            loadedRequest = request
        } catch {
            guard !Task.isCancelled else { return }
            candidates = []
            loadedRequest = nil
            failedRequest = request
        }
    }

    private func kindLabel(_ kind: CredentialCandidate.Kind) -> String {
        switch kind {
        case .password: "密码"
        case .oneTimeCode: "验证码"
        case .passkey: "通行密钥"
        }
    }
}

private struct ExtensionCloseButton: View {
    let action: () -> Void

    var body: some View {
        Button(role: .cancel, action: action) {
            Label("关闭", systemImage: "xmark")
                .labelStyle(.iconOnly)
                .frame(minWidth: 44, minHeight: 44)
        }
        .buttonStyle(.glass)
        .buttonBorderShape(.circle)
        .keyboardShortcut(.cancelAction)
        .accessibilityIdentifier("autofill.close")
    }
}

struct ConfigurationView: View {
    let onDone: () -> Void

    var body: some View {
        ScrollView {
            VStack(spacing: Spacing.lg) {
                OpenVaultMark(size: 64)
                Text("OpenVault 自动填充")
                    .font(.title.bold()).accessibilityAddTraits(.isHeader)
                Text("在 OpenVault 中登录、同步保险库并启用生物识别后，即可填充密码、通行密钥和验证码。")
                    .font(.body).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                Button("完成", action: onDone)
                    .vaultProminentButtonStyle()
                    .controlSize(.large)
                    .buttonBorderShape(.capsule)
            }
            .frame(maxWidth: 400)
            .frame(maxWidth: .infinity)
            .padding(Spacing.xl)
        }
        .scrollBounceBehavior(.basedOnSize)
        .background(Palette.groupedBackground)
    }
}
