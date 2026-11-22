import SwiftUI
import DesignSystem
import VaultRepository

private enum SendFilter: CaseIterable {
    case all, text, file

    var title: String {
        switch self {
        case .all: "全部"
        case .text: "文本"
        case .file: "文件"
        }
    }

    func includes(_ send: VaultSend) -> Bool {
        self == .all || (self == .text && send.kind == .text) || (self == .file && send.kind == .file)
    }
}

private extension VaultSend {
    var kindName: String { kind == .text ? "文本" : "文件" }
    var symbol: String { kind == .text ? "doc.text" : "doc" }
    var accesses: String { maxAccessCount.map { "\(accessCount)/\($0)" } ?? "\(accessCount)" }

    func stateLabel(at date: Date) -> String? {
        if disabled { return "已停用" }
        if deletionDate <= date || expirationDate.map({ $0 <= date }) == true { return "已过期" }
        if let maxAccessCount, accessCount >= maxAccessCount { return "已达访问上限" }
        return nil
    }
}

@MainActor
private enum SendClipboard {
    static func copy(_ value: String) {
        #if os(macOS)
        MacClipboard.copy(value)
        #else
        Clipboard.copy(value)
        #endif
    }
}

private struct SendSelection: Identifiable {
    let id: String
}

struct SendWorkspace: View {
    let service: (any VaultSendService)?
    @Binding var showComposer: Bool
    var query = ""
    var onCountChange: ((Int) -> Void)?
    var dataRevision: UInt64 = 0

    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var sizeClass
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor
    #endif
    @State private var items: [VaultSend] = []
    @State private var selectedID: String?
    @State private var selectionSheet: SendSelection?
    @State private var filter: SendFilter = .all
    @State private var loading = true
    @State private var loadFailed = false
    @State private var revision = UUID()
    @State private var feedback: String?
    @State private var feedbackID = UUID()

    private var compact: Bool {
        #if os(macOS)
        false
        #else
        sizeClass != .regular
        #endif
    }

    private var visible: [VaultSend] {
        let term = query.trimmingCharacters(in: .whitespacesAndNewlines)
        return items.filter {
            filter.includes($0) && (term.isEmpty || $0.name.localizedStandardContains(term)
                || ($0.fileName?.localizedStandardContains(term) ?? false))
        }
    }

    private var selectedItem: VaultSend? { visible.first { $0.id == selectedID } }

    var body: some View {
        Group {
            if compact { itemList }
            else {
                GeometryReader { proxy in
                    HStack(spacing: 0) {
                        itemList.frame(width: listWidth(in: proxy.size.width))
                        Divider()
                        if let selectedItem { detail(for: selectedItem, isSheet: false) }
                        else {
                            ContentUnavailableView("选择一个 Send", systemImage: "paperplane")
                                .frame(maxWidth: .infinity, maxHeight: .infinity)
                        }
                    }
                }
            }
        }
        .navigationTitle("Send")
        #if os(iOS)
        .toolbarTitleDisplayMode(compact ? .inlineLarge : .large)
        #endif
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("新建 Send", systemImage: "plus") { showComposer = true }
                    .accessibilityIdentifier("send.new")
            }
        }
        .copyToast(feedback)
        .task(id: feedbackID) {
            guard feedback != nil else { return }
            try? await Task.sleep(for: .seconds(2.4))
            if !Task.isCancelled { feedback = nil }
        }
        .task(id: dataRevision) { await reload() }
        .onChange(of: visible.map(\.id), initial: true) { _, ids in
            if selectedID.map({ ids.contains($0) }) != true { selectedID = ids.first }
        }
        .onChange(of: compact) { _, value in
            if !value { selectionSheet = nil }
        }
        .sheet(isPresented: $showComposer) {
            SendEditor(service: service) { send in
                filter = .all
                selectedID = send.id
                updated(send)
                SendClipboard.copy(send.shareURL.absoluteString)
                announce("已创建，链接已拷贝")
            }
        }
        .sheet(item: $selectionSheet) { selection in
            if let send = items.first(where: { $0.id == selection.id }) {
                NavigationStack { detail(for: send, isSheet: true) }
                    #if os(iOS)
                    .presentationDetents([.medium, .large])
                    .presentationDragIndicator(.visible)
                    #endif
            }
        }
    }

    private func listWidth(in available: CGFloat) -> CGFloat {
        #if os(macOS)
        min(316, available * 0.43)
        #else
        min(380, available * 0.43)
        #endif
    }

    private func detail(for item: VaultSend, isSheet: Bool) -> some View {
        SendDetails(send: item, service: service, isSheet: isSheet, onChanged: updated,
                    onDeleted: { id in
                        revision = UUID()
                        items.removeAll { $0.id == id }
                        selectionSheet = nil
                        onCountChange?(items.count)
                        announce("已删除 Send")
                    })
            .id(item.id)
    }

    private var itemList: some View {
        VStack(spacing: 0) {
            filters.padding(.horizontal).padding(.vertical, 8)
            if !visible.isEmpty {
                if compact { phoneRows }
                else {
                    List(visible, selection: $selectedID) { item in
                        SendSummary(send: item).tag(item.id)
                    }
                    .listStyle(.plain)
                    .refreshable { await reload() }
                }
            } else if loading {
                ProgressView("正在读取 Send…").frame(maxWidth: .infinity, maxHeight: .infinity)
            } else { emptyList }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        #if os(iOS)
        .background(Palette.groupedBackground)
        #endif
    }

    private var phoneRows: some View {
        List(visible) { item in
            HStack {
                Button {
                    selectedID = item.id
                    selectionSheet = SendSelection(id: item.id)
                } label: {
                    SendSummary(send: item).frame(maxWidth: .infinity, minHeight: 56, alignment: .leading).contentShape(.rect)
                }
                .buttonStyle(.plain)
                InlineCopyButton(action: { SendClipboard.copy(item.shareURL.absoluteString) }) { copied in
                    Group {
                        if copied { InlineCopyIndicator() }
                        else { Image(systemName: "link").font(.body.weight(.semibold)) }
                    }
                    .padding(.horizontal, 8)
                    .frame(minWidth: 44, minHeight: 44)
                    .background(Palette.controlFill, in: Capsule())
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("拷贝“\(item.name)”的链接")
            }
        }
        #if os(iOS)
        .listStyle(.insetGrouped)
        .contentMargins(.top, 4, for: .scrollContent)
        #endif
        .refreshable { await reload() }
    }

    @ViewBuilder
    private var filters: some View {
        #if os(macOS)
        Picker("Send 类型", selection: $filter) {
            ForEach(SendFilter.allCases, id: \.self) { Text($0.title).tag($0) }
        }
        .pickerStyle(.segmented).labelsHidden()
        #else
        ScrollView(.horizontal) {
            HStack(spacing: 8) {
                ForEach(SendFilter.allCases, id: \.self) { choice in
                    let selected = choice == filter
                    let selectedForeground: Color = colorScheme == .dark && contrast == .increased ? .black : .white
                    Button {
                        filter = choice
                    } label: {
                        HStack(spacing: 5) {
                            if selected && differentiateWithoutColor { Image(systemName: "checkmark").accessibilityHidden(true) }
                            Text(choice.title).fontWeight(.medium)
                            if !loading, !loadFailed, service != nil {
                                Text(items.count(where: choice.includes), format: .number).monospacedDigit()
                            }
                        }
                        .font(.subheadline)
                        .padding(.horizontal, 14).padding(.vertical, 8)
                        .foregroundStyle(selected ? selectedForeground : Palette.primaryText)
                        .background(selected ? Color.accentColor : Palette.controlFill, in: Capsule())
                        .frame(minHeight: 44)
                        .contentShape(.rect)
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(selected ? .isSelected : [])
                }
            }
        }
        .scrollIndicators(.hidden)
        #endif
    }

    private var emptyList: some View {
        Group {
            if service == nil {
                ContentUnavailableView("Send 暂不可用", systemImage: "paperplane",
                                       description: Text("当前无法读取或共享 Send。"))
            } else if loadFailed {
                ContentUnavailableView {
                    Label("无法读取 Send", systemImage: "exclamationmark.circle")
                } actions: { Button("重试") { Task { await reload() } } }
            } else if !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                ContentUnavailableView.search(text: query)
            } else {
                ContentUnavailableView(filter == .all ? "暂无 Send" : "暂无\(filter.title) Send",
                                       systemImage: "paperplane", description: Text("新建 Send 来共享文本或文件。"))
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func updated(_ send: VaultSend) {
        revision = UUID()
        loading = false
        loadFailed = false
        items.removeAll { $0.id == send.id }
        items.insert(send, at: 0)
        onCountChange?(items.count)
    }

    private func reload() async {
        let request = UUID()
        revision = request
        loading = true
        defer { if revision == request { loading = false } }
        guard let service else { return }
        do {
            let records = try await service.listSends()
            guard !Task.isCancelled, revision == request else { return }
            items = records
            loadFailed = false
            onCountChange?(records.count)
        } catch {
            guard !Task.isCancelled, revision == request else { return }
            loadFailed = true
            if !items.isEmpty { announce("无法刷新 Send") }
        }
    }

    private func announce(_ value: String) {
        feedback = value
        feedbackID = UUID()
    }
}

private struct SendSummary: View {
    let send: VaultSend

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: send.symbol)
                .foregroundStyle(.secondary)
                .frame(width: 36, height: 36)
                .background(Palette.controlFill, in: .rect(cornerRadius: 10))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(send.name).font(.body.weight(.medium)).lineLimit(2)
                Text("\(send.deletionDate, style: .relative)后删除 · 已访问 \(send.accesses) 次")
                    .font(.footnote).foregroundStyle(.secondary)
                if let badge = send.stateLabel(at: .now) ?? (send.hasPassword ? "有密码" : nil) {
                    Text(badge).font(.caption.weight(.medium))
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Palette.controlFill, in: Capsule())
                }
            }
        }
        .frame(minHeight: 52, alignment: .leading)
        .accessibilityElement(children: .combine)
        .privacySensitive()
    }
}

private struct SendDetails: View {
    let send: VaultSend
    let service: (any VaultSendService)?
    let isSheet: Bool
    let onChanged: (VaultSend) -> Void
    let onDeleted: (String) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var editing = false
    @State private var confirmDelete = false
    @State private var confirmRemovePassword = false
    @State private var busy = false
    @State private var failure: String?
    @State private var operation: Task<Void, Never>?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if !isSheet {
                    Label {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(send.name).font(.title.bold()).textSelection(.enabled)
                            Text("\(send.kindName) Send").font(.subheadline).foregroundStyle(.secondary)
                        }
                    } icon: {
                        Image(systemName: send.symbol).font(.title2)
                            .frame(width: 52, height: 52)
                            .background(Palette.controlFill, in: .rect(cornerRadius: 14))
                    }
                }
                if let state = send.stateLabel(at: .now) {
                    Label("\(state) · 接收者无法打开", systemImage: "exclamationmark.circle")
                        .font(.callout).foregroundStyle(.secondary)
                }
                card {
                    copyField(title: "共享链接", value: send.shareURL.absoluteString)
                    if !isSheet {
                        Divider()
                        ShareLink(item: send.shareURL) { Label("共享…", systemImage: "square.and.arrow.up") }
                            .buttonStyle(.borderless)
                            .padding(.horizontal, 14).frame(minHeight: rowHeight)
                    }
                }
                if !isSheet {
                    if send.kind == .text, let text = send.text { card { copyField(title: "文本", value: text) } }
                    else if let name = send.fileName { card { info("文件", name) } }
                }
                card {
                    info("删除时间", send.deletionDate.formatted(date: .abbreviated, time: .shortened))
                    Divider()
                    info("过期时间", send.expirationDate?.formatted(date: .abbreviated, time: .shortened) ?? "不过期")
                    Divider()
                    info("访问次数", send.accesses)
                    Divider()
                    info("访问密码", send.hasPassword ? "已设置" : "未设置")
                    if !isSheet {
                        Divider()
                        info("我的邮箱", send.hideEmail ? "对接收者隐藏" : "显示给接收者")
                        if send.kind == .text {
                            Divider()
                            info("显示方式", send.hideText ? "接收者需点按才显示文本" : "直接显示文本")
                        }
                    }
                }
                if !isSheet, let notes = send.notes, !notes.isEmpty { card { info("私人备注", notes) } }
                if isSheet {
                    HStack {
                        ShareLink(item: send.shareURL) {
                            Label("共享…", systemImage: "square.and.arrow.up").frame(maxWidth: .infinity)
                        }
                        Button(role: .destructive) { confirmDelete = true } label: {
                            Label("删除", systemImage: "trash").frame(maxWidth: .infinity)
                        }
                        .disabled(busy || service == nil)
                    }
                    .buttonStyle(.bordered).controlSize(.large)
                }
            }
            .padding()
            .frame(maxWidth: 560)
            .frame(maxWidth: .infinity)
        }
        .privacySensitive()
        #if os(iOS)
        .background(Palette.groupedBackground)
        #endif
        .toolbar {
            if isSheet {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭", systemImage: "xmark") { dismiss() }
                }
                ToolbarItem(placement: .principal) { Text(send.name).font(.headline).lineLimit(1) }
            }
            ToolbarItemGroup(placement: .primaryAction) {
                Button("编辑", systemImage: "pencil") { editing = true }.disabled(busy)
                if !isSheet {
                    #if os(iOS)
                    Menu("共享", systemImage: "square.and.arrow.up") {
                        Button("拷贝链接", systemImage: "link") { SendClipboard.copy(send.shareURL.absoluteString) }
                        ShareLink(item: send.shareURL) { Label("共享…", systemImage: "square.and.arrow.up") }
                    }
                    #else
                    Button("删除 Send", systemImage: "trash", role: .destructive) { confirmDelete = true }
                        .disabled(busy)
                    #endif
                    Menu("更多", systemImage: "ellipsis.circle") {
                        if send.hasPassword { Button("移除访问密码…") { confirmRemovePassword = true } }
                        Button(send.disabled ? "重新启用" : "停用") { changeAccess(removePassword: false) }
                        Divider()
                        Button("删除…", role: .destructive) { confirmDelete = true }
                    }
                    .disabled(busy)
                }
            }
        }
        .sheet(isPresented: $editing) { SendEditor(service: service, item: send, onSaved: onChanged) }
        .onDisappear { operation?.cancel() }
        .confirmationDialog("删除“\(send.name)”？", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("删除", role: .destructive, action: delete)
            Button("取消", role: .cancel) {}
        } message: { Text("链接会立即失效，接收者将无法再打开。") }
        .confirmationDialog("移除访问密码？", isPresented: $confirmRemovePassword, titleVisibility: .visible) {
            Button("移除密码", role: .destructive) { changeAccess(removePassword: true) }
            Button("取消", role: .cancel) {}
        } message: { Text("任何持有有效链接的人都将不再需要密码即可访问。") }
        .alert("无法完成操作", isPresented: Binding(get: { failure != nil }, set: { if !$0 { failure = nil } })) {
            Button("好", role: .cancel) { failure = nil }
        } message: { Text(failure ?? "") }
        .interactiveDismissDisabled(isSheet && busy)
    }

    private var rowHeight: CGFloat {
        #if os(macOS)
        38
        #else
        52
        #endif
    }

    private func card<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        #if os(macOS)
        let radius = CornerRadius.macCard
        #else
        let radius = isSheet ? CornerRadius.iPhoneCard : CornerRadius.iPadCard
        #endif
        return OpenVaultCard(cornerRadius: radius, padding: 0) {
            VStack(alignment: .leading, spacing: 0, content: content)
        }
    }

    private func info(_ title: String, _ value: String) -> some View {
        LabeledContent(title) { Text(value).multilineTextAlignment(.trailing) }
            .padding(.horizontal, 14).padding(.vertical, 4)
            .frame(minHeight: rowHeight)
    }

    private func copyField(title: String, value: String) -> some View {
        InlineCopyButton(action: { SendClipboard.copy(value) }) { copied in
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(.footnote).foregroundStyle(.secondary)
                    Text(value).font(.body).lineLimit(isSheet ? 1 : 3).truncationMode(.middle)
                }
                Spacer()
                if copied { InlineCopyIndicator() }
            }
            .padding(.horizontal, 14).padding(.vertical, 8)
            .frame(minHeight: rowHeight).contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityLabel("拷贝\(title)")
    }

    private func delete() {
        guard let service, !busy else { return }
        busy = true
        operation = Task { @MainActor in
            defer { busy = false }
            do {
                try await service.deleteSend(id: send.id)
                guard !Task.isCancelled else { return }
                onDeleted(send.id)
            } catch {
                if !Task.isCancelled { failure = SendFailure.message(for: error) }
            }
        }
    }

    private func changeAccess(removePassword: Bool) {
        guard let service, !busy else { return }
        var value = VaultSendDraft(editing: send)
        if removePassword { value.removePassword = true }
        else { value.disabled.toggle() }
        busy = true
        operation = Task { @MainActor in
            defer { busy = false }
            do {
                let updated = try await service.updateSend(id: send.id, draft: value)
                guard !Task.isCancelled else { return }
                onChanged(updated)
            } catch {
                if !Task.isCancelled { failure = SendFailure.message(for: error) }
            }
        }
    }
}
