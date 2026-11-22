import SwiftUI
import DesignSystem
import Networking
import UIShared
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

extension VaultSend {
    func matchesWorkspaceSearch(_ query: String) -> Bool {
        let term = query.trimmingCharacters(in: .whitespacesAndNewlines)
        return term.isEmpty || name.localizedStandardContains(term)
            || notes?.localizedStandardContains(term) == true || fileName?.localizedStandardContains(term) == true
    }
}

@MainActor
enum SendWorkspaceSelection {
    static func apply(_ saved: VaultSend, selecting: Bool, selectedID: inout String?, query: inout String) {
        if selecting { selectedID = saved.id }
        if selectedID == saved.id, !saved.matchesWorkspaceSearch(query) { query = "" }
    }

    static func scopedQuery(_ source: Binding<String>, isActive: @escaping () -> Bool) -> Binding<String> {
        Binding(get: { isActive() ? source.wrappedValue : "" }, set: { value in
            if isActive(), source.wrappedValue != value { source.wrappedValue = value }
        })
    }
}

private extension VaultSend {
    var kindName: String { kind == .text ? "文本" : "文件" }
    var symbol: String { kind == .text ? "doc.text" : "doc" }
    var accesses: String { maxAccessCount.map { "\(accessCount)/\($0)" } ?? "\(accessCount)" }
    var statusChanges: [Date] { ([.distantPast, deletionDate] + [expirationDate].compactMap { $0 }).sorted() }

    func isExpired(at date: Date) -> Bool {
        deletionDate <= date || expirationDate.map { $0 <= date } == true
    }

    func stateLabel(at date: Date) -> String? {
        if disabled { return "已停用" }
        if isExpired(at: date) { return "已过期" }
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

@MainActor @Observable
final class SendWorkspaceRecords {
    enum State: Equatable {
        case loading, complete(Int), failed, unavailable

        var count: Int? {
            if case let .complete(count) = self { return count }
            return nil
        }
    }

    private(set) var items: [VaultSend] = []
    private(set) var state: State = .loading
    private(set) var authorizationRevision: UInt64 = 0
    @ObservationIgnored private var readID: UUID?
    @ObservationIgnored private var changedDuringRead: Set<String> = []
    @ObservationIgnored private weak var syncAccess: VaultSyncAccess?
    @ObservationIgnored private var scope: AccountSessionLease?
    @ObservationIgnored private var observer: UUID?

    func store(_ send: VaultSend) {
        items.removeAll { $0.id == send.id }
        items.insert(send, at: 0)
        changed(send.id)
    }

    func remove(_ id: String) {
        items.removeAll { $0.id == id }
        changed(id)
    }

    private func changed(_ id: String) {
        if readID != nil { changedDuringRead.insert(id) }
        if state.count != nil { state = .complete(items.count); publishCount() }
    }

    func clear() {
        if let observer { syncAccess?.removeObserver(observer) }
        observer = nil
        syncAccess = nil
        scope = nil
        reset(to: .loading)
    }

    private func reset(to next: State) {
        readID = nil
        changedDuringRead.removeAll()
        items = []
        state = next
        authorizationRevision &+= 1
    }

    private func publishCount() {
        if let syncAccess, let scope { syncAccess.recordSendCount(state.count, for: scope, revision: syncAccess.sendRevision) }
    }

    func read(from service: (any VaultSendService)?, access: VaultSyncAccess? = nil) async {
        guard !Task.isCancelled else { return }
        guard let service else { clear(); state = .unavailable; return }
        if let access {
            let active = await access.session()
            guard !Task.isCancelled else { return }
            guard let active else { reset(to: .failed); return }
            if scope != active || syncAccess !== access {
                if observer != nil { clear() }
                syncAccess = access
                scope = active
                observer = access.observe(active) { [weak self] in self?.reset(to: .failed) }
            }
        }
        let request = UUID()
        readID = request
        changedDuringRead.removeAll()
        state = .loading
        defer {
            if readID == request { readID = nil; changedDuringRead.removeAll() }
        }
        do {
            let snapshot = try await service.listSends()
            guard readID == request else { return }
            guard !Task.isCancelled else { state = .failed; return }
            items = items.filter { changedDuringRead.contains($0.id) } + snapshot.filter { !changedDuringRead.contains($0.id) }
            state = .complete(items.count)
            publishCount()
        } catch {
            guard readID == request else { return }
            if VaultSyncAccess.deniesAccess(error) {
                if let access, let scope { await access.deny(scope) }
                if readID == request { reset(to: .failed) }
                return
            }
            switch error {
            case RepositoryError.locked, RepositoryError.notAuthenticated, RepositoryError.authenticationFailed,
                 NetworkingError.accountContextChanged: reset(to: .failed)
            default: break
            }
            state = .failed
            publishCount()
        }
    }
}

private struct SendReadTrigger: Equatable {
    let revision: UInt64
    let retry: UInt64
    let serviceAvailable: Bool
}

struct SendWorkspace: View {
    let service: (any VaultSendService)?
    @Binding var showComposer: Bool
    @Binding var query: String
    var onCountChange: ((Int?) -> Void)?
    var dataRevision: UInt64 = 0
    let syncAccess: VaultSyncAccess?

    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var sizeClass
    @Environment(\.tabBarPlacement) private var tabBarPlacement
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor
    #endif
    @State private var records: SendWorkspaceRecords
    @State private var selectedID: String?
    @State private var selectionSheet: SendSelection?
    @State private var filter: SendFilter = .all
    @State private var retryRevision: UInt64 = 0
    @State private var lastReadTrigger: SendReadTrigger?
    @State private var lastSuccessfulSync: UInt64 = 0
    @State private var feedback: String?
    @State private var feedbackID = UUID()

    init(service: (any VaultSendService)?, showComposer: Binding<Bool>, query: Binding<String>,
         onCountChange: ((Int?) -> Void)? = nil, dataRevision: UInt64 = 0, syncAccess: VaultSyncAccess? = nil,
         records: SendWorkspaceRecords = .init()) {
        self.service = service
        _showComposer = showComposer
        _query = query
        self.onCountChange = onCountChange
        self.dataRevision = dataRevision
        self.syncAccess = syncAccess
        _records = State(initialValue: records)
    }

    private var compact: Bool {
        #if os(macOS)
        false
        #else
        sizeClass != .regular
        #endif
    }

    private var visible: [VaultSend] {
        guard service != nil else { return [] }
        return records.items.filter { filter.includes($0) && $0.matchesWorkspaceSearch(query) }
    }

    private var selectedItem: VaultSend? { visible.first { $0.id == selectedID } }

    var body: some View {
        let authorization = records.authorizationRevision
        let readTrigger = SendReadTrigger(revision: dataRevision, retry: retryRevision, serviceAvailable: service != nil)
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
        #if os(iOS)
        .navigationTitle(compact ? "Send" : "")
        .toolbarTitleDisplayMode(compact ? .inlineLarge : .inline)
        .toolbar {
            if compact {
                ToolbarItem(placement: .primaryAction) { newButton }
            }
        }
        #else
        .navigationTitle("Send")
        #endif
        .copyToast(feedback)
        .task(id: feedbackID) {
            guard feedback != nil else { return }
            try? await Task.sleep(for: .seconds(2.4))
            if !Task.isCancelled { feedback = nil }
        }
        .task(id: readTrigger) {
            let preceding = lastReadTrigger
            lastReadTrigger = readTrigger
            let hadSuccessfulSync = lastSuccessfulSync != (syncAccess?.successfulSyncs ?? 0)
            lastSuccessfulSync = syncAccess?.successfulSyncs ?? 0
            if let preceding, preceding.retry == readTrigger.retry, preceding.serviceAvailable == readTrigger.serviceAvailable,
               !hadSuccessfulSync, records.state == .failed, syncAccess?.sendListingDenied == true { return }
            await records.read(from: service, access: syncAccess)
        }
        .onChange(of: records.state, initial: true) { _, state in onCountChange?(state.count) }
        .onDisappear { records.clear(); lastReadTrigger = nil }
        .onChange(of: authorization) { _, _ in
            selectionSheet = nil
            selectedID = nil
            showComposer = false
            feedback = nil
        }
        .onChange(of: visible.map(\.id), initial: true) { _, ids in
            if selectedID.map({ ids.contains($0) }) != true { selectedID = ids.first }
        }
        .onChange(of: records.items.map(\.id)) { _, ids in
            if let selectionSheet, !ids.contains(selectionSheet.id) { self.selectionSheet = nil }
        }
        .onChange(of: compact) { _, value in
            if !value { selectionSheet = nil }
        }
        .sheet(isPresented: $showComposer) {
            SendEditor(service: service) { send in
                guard authorization == records.authorizationRevision else { return }
                filter = .all
                updated(send, select: true)
                SendClipboard.copy(send.shareURL.absoluteString)
                announce("已创建，链接已拷贝")
            }
        }
        .sheet(item: $selectionSheet) { selection in
            if service != nil, let send = records.items.first(where: { $0.id == selection.id }) {
                NavigationStack {
                    detail(for: send, isSheet: true)
                        #if os(iOS)
                        .navigationBarTitleDisplayMode(.inline)
                        #endif
                }
                #if os(iOS)
                .presentationDetents([.fraction(0.66), .large])
                .presentationDragIndicator(.visible)
                #endif
            }
        }
    }

    private func listWidth(in available: CGFloat) -> CGFloat {
        #if os(macOS)
        min(LayoutMetric.desktopListWidth, available * 0.43)
        #else
        min(tabBarPlacement == .sidebar ? LayoutMetric.padListWidthWithSidebar : LayoutMetric.padListWidth,
            available * 0.43)
        #endif
    }

    private func detail(for item: VaultSend, isSheet: Bool) -> some View {
        let authorization = records.authorizationRevision
        return SendDetails(send: item, service: service, isSheet: isSheet, onChanged: { send in
            if authorization == records.authorizationRevision { updated(send) }
        },
                    onDeleted: { id in
                        guard authorization == records.authorizationRevision else { return }
                        records.remove(id)
                        selectionSheet = nil
                        announce("已删除 Send")
                    })
            .id(item.id)
    }

    private var itemList: some View {
        VStack(spacing: 0) {
            #if os(iOS)
            if !compact {
                HStack {
                    Text("Send").font(.title.bold()).accessibilityAddTraits(.isHeader)
                    Spacer()
                    newButton.labelStyle(.iconOnly).buttonStyle(.glass).buttonBorderShape(.circle).controlSize(.large)
                }
                .padding(.horizontal, 20).padding(.top, Spacing.lg)
            }
            filters.padding(.horizontal).padding(.vertical, 8)
            #else
            HStack(spacing: Spacing.sm) {
                filters
                newButton
                    .labelStyle(.iconOnly)
                    .buttonStyle(.glass)
                    .buttonBorderShape(.circle)
                    .controlSize(.regular)
                    .disabled(service == nil)
                    .help("新建 Send")
            }
            .padding(.horizontal, Spacing.lg).padding(.vertical, Spacing.sm)
            #endif
            if !visible.isEmpty {
                if records.state == .failed {
                    HStack {
                        Label("无法读取完整的 Send 列表", systemImage: "exclamationmark.circle")
                        Spacer()
                        retryButton
                    }
                    .font(.callout).padding(.horizontal).padding(.vertical, Spacing.sm)
                }
                if compact { phoneRows }
                else {
                    #if os(iOS)
                    padRows
                    #else
                    List(visible, selection: $selectedID) { item in
                        SendSummary(send: item).tag(item.id)
                    }
                    .listStyle(.plain)
                    .refreshable { await records.read(from: service, access: syncAccess) }
                    #endif
                }
            } else { emptyList }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        #if os(iOS)
        .background(compact ? Palette.groupedBackground : Palette.contentBackground)
        #endif
    }

    private var newButton: some View {
        Button("新建 Send", systemImage: "plus") { showComposer = true }
            .accessibilityIdentifier("send.new")
    }

    #if os(iOS)
    private var padRows: some View {
        List(visible) { item in
            let selected = selectedID == item.id
            Button { selectedID = item.id } label: {
                SendSummary(send: item, isPadRow: true)
                    .padding(.horizontal, 12)
                    .frame(maxWidth: .infinity, minHeight: 66, alignment: .leading)
                    .background(selected ? Color.accentColor.opacity(contrast == .increased ? 0.26 : 0.14) : .clear,
                                in: .rect(cornerRadius: CornerRadius.md))
                    .overlay {
                        if selected && differentiateWithoutColor {
                            RoundedRectangle(cornerRadius: CornerRadius.md).strokeBorder(.primary, lineWidth: 1)
                                .allowsHitTesting(false)
                        }
                    }
                    .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .accessibilityAddTraits(selected ? .isSelected : [])
            .listRowInsets(EdgeInsets(top: 1, leading: 8, bottom: 1, trailing: 8))
            .listRowSeparator(.hidden)
            .listRowBackground(Color.clear)
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .refreshable { await records.read(from: service, access: syncAccess) }
    }
    #endif

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
            .listRowInsets(EdgeInsets(top: 8, leading: 16, bottom: 8, trailing: 16))
        }
        #if os(iOS)
        .listStyle(.insetGrouped)
        .contentMargins(.top, 4, for: .scrollContent)
        .contentMargins(.horizontal, Spacing.lg, for: .scrollContent)
        #endif
        .refreshable { await records.read(from: service, access: syncAccess) }
    }

    @ViewBuilder
    private var filters: some View {
        #if os(macOS)
        MacSegmentedPicker("Send 类型", options: SendFilter.allCases, selection: $filter, title: \.title)
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
                            if records.state.count != nil, service != nil {
                                Text(records.items.count(where: choice.includes), format: .number).monospacedDigit()
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
            if service == nil || records.state == .unavailable {
                ContentUnavailableView("Send 暂不可用", systemImage: "paperplane",
                                       description: Text("当前无法读取或共享 Send。"))
            } else if records.state == .loading {
                ProgressView("正在读取 Send…")
            } else if records.state == .failed {
                ContentUnavailableView {
                    Label("无法读取 Send", systemImage: "exclamationmark.circle")
                } description: {
                    Text("无法确认完整列表，请重试。")
                } actions: { retryButton }
            } else if !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                ContentUnavailableView.search(text: query)
            } else {
                ContentUnavailableView(filter == .all ? "暂无 Send" : "暂无\(filter.title) Send",
                                       systemImage: "paperplane", description: Text("新建 Send 来共享文本或文件。"))
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var retryButton: some View {
        Button("重试") { retryRevision &+= 1 }.accessibilityIdentifier("send.retry")
    }

    private func updated(_ send: VaultSend, select: Bool = false) {
        records.store(send)
        SendWorkspaceSelection.apply(send, selecting: select, selectedID: &selectedID, query: &query)
    }

    private func announce(_ value: String) {
        feedback = value
        feedbackID = UUID()
    }
}

struct SendRemainingTime: DiscreteFormatStyle {
    let deadline: Date
    var units = Duration.UnitsFormatStyle(allowedUnits: [.days, .hours, .minutes], width: .abbreviated,
                                          maximumUnitCount: 1, fractionalPart: .hide(rounded: .up))

    func format(_ now: Date) -> String { units.format(remaining(at: now)) }

    func discreteInput(before now: Date) -> Date? { units.discreteInput(after: remaining(at: now)).map(date) }
    func discreteInput(after now: Date) -> Date? { units.discreteInput(before: remaining(at: now)).map(date) }

    func locale(_ locale: Locale) -> Self { Self(deadline: deadline, units: units.locale(locale)) }

    private func remaining(at now: Date) -> Duration { .seconds(deadline.timeIntervalSince(now)) }

    private func date(_ remaining: Duration) -> Date {
        let parts = remaining.components
        return deadline.addingTimeInterval(-Double(parts.seconds) - Double(parts.attoseconds) / 1e18)
    }
}

private struct SendSummary: View {
    let send: VaultSend
    var isPadRow = false
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    var body: some View {
        TimelineView(.explicit(send.statusChanges)) { context in
            row(at: context.date)
        }
        .accessibilityElement(children: .combine)
        .privacySensitive()
    }

    private func row(at date: Date) -> some View {
        #if os(macOS)
        let iconSize: CGFloat = 30
        let placesBadgeAtEnd = true
        #else
        let iconSize: CGFloat = isPadRow ? 38 : 36
        let placesBadgeAtEnd = isPadRow && !dynamicTypeSize.isAccessibilitySize
        #endif
        let subdued = isPadRow && (send.disabled || send.isExpired(at: date))
        let badge = send.stateLabel(at: date) ?? (send.hasPassword ? "有密码" : nil)
        return HStack(spacing: 12) {
            Image(systemName: send.symbol)
                .foregroundStyle(isPadRow && !subdued ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                .frame(width: iconSize, height: iconSize)
                .background(Palette.controlFill, in: .rect(cornerRadius: 10))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(send.name).font(.body.weight(.medium)).lineLimit(2)
                    .foregroundStyle(subdued ? .secondary : .primary)
                ViewThatFits(in: .horizontal) {
                    HStack(spacing: 3) {
                        deletionLabel(at: date)
                        Text("·")
                        Text("访问 \(send.accesses) 次")
                    }
                    .fixedSize(horizontal: true, vertical: false)
                    VStack(alignment: .leading, spacing: 0) {
                        deletionLabel(at: date)
                        Text("访问 \(send.accesses) 次")
                    }
                    .fixedSize(horizontal: false, vertical: true)
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(Text("删除时间：\(send.deletionDate.formatted(date: .abbreviated, time: .shortened))，已访问 \(send.accesses) 次"))
                .font(.subheadline).foregroundStyle(.secondary)
                if !placesBadgeAtEnd, let badge { badgeLabel(badge) }
            }
            if placesBadgeAtEnd, let badge { Spacer(minLength: 0); badgeLabel(badge) }
        }
        .frame(minHeight: 52, alignment: .leading)
    }

    private func deletionLabel(at date: Date) -> Text {
        if date >= send.deletionDate { return Text("已到删除时间") }
        return Text("\(TimeDataSource<Date>.currentDate, format: SendRemainingTime(deadline: send.deletionDate))后删除")
    }

    private func badgeLabel(_ title: String) -> some View {
        Text(title).font(.caption.weight(.medium))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(Palette.controlFill, in: Capsule())
    }
}

private struct SendDetails: View {
    let send: VaultSend
    let service: (any VaultSendService)?
    let isSheet: Bool
    let onChanged: (VaultSend) -> Void
    let onDeleted: (String) -> Void

    @Environment(\.dismiss) private var dismiss
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @State private var editing = false
    @State private var confirmDelete = false
    @State private var confirmRemovePassword = false
    @State private var busy = false
    @State private var failure: String?
    @State private var operation: Task<Void, Never>?

    var body: some View {
        TimelineView(.explicit(send.statusChanges)) { context in
            #if os(macOS)
            MacDetailColumn { detailContent(at: context.date) }
            #else
            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.lg) { detailContent(at: context.date) }
                    .padding(isSheet ? Spacing.lg : Spacing.xl)
                    .frame(maxWidth: LayoutMetric.padDetailWidth)
                    .frame(maxWidth: .infinity)
            }
            #endif
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
                Button("编辑", systemImage: "pencil") { editing = true }
                    #if os(iOS)
                    .labelStyle(.titleOnly)
                    #endif
                    .disabled(busy || service == nil)
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
        #if os(macOS)
        .focusedSceneValue(\.macSendActions, busy || editing || confirmDelete || confirmRemovePassword || failure != nil || service == nil
            ? nil : MacSendCommandActions(edit: { editing = true }, delete: { confirmDelete = true }))
        #endif
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

    @ViewBuilder private func detailContent(at date: Date) -> some View {
        if !isSheet {
            HStack(spacing: Spacing.lg) {
                Image(systemName: send.symbol).font(.title)
                    #if os(iOS)
                    .foregroundStyle(.tint)
                    #else
                    .foregroundStyle(.secondary)
                    #endif
                    .frame(width: 64, height: 64)
                    .background(Palette.controlFill, in: .rect(cornerRadius: 16))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: Spacing.xs) {
                    Text(send.name)
                        #if os(macOS)
                        .font(.system(size: 26, weight: .bold))
                        #else
                        .font(.title.bold())
                        #endif
                        .textSelection(.enabled).accessibilityAddTraits(.isHeader)
                    Text("\(send.kindName) · \(send.revisionDate, format: .dateTime.month().day())修改")
                        .font(.subheadline).foregroundStyle(.secondary)
                }
            }
        }
        if let state = send.stateLabel(at: date) {
            Label("\(state) · 接收者无法打开", systemImage: "exclamationmark.circle")
                .font(.callout).foregroundStyle(.secondary)
        }
        #if os(macOS)
        card {
            VStack(alignment: .leading, spacing: Spacing.xs) {
                Text("共享链接").font(.subheadline).foregroundStyle(.secondary)
                Text(send.shareURL.absoluteString).font(Typography.secretValue)
                    .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                HStack(spacing: Spacing.sm) {
                    InlineCopyButton(action: { SendClipboard.copy(send.shareURL.absoluteString) }) { copied in
                        Label(copied ? "已拷贝" : "拷贝链接", systemImage: copied ? "checkmark" : "link")
                    }
                    .vaultProminentButtonStyle()
                    .accessibilityLabel("拷贝共享链接")
                    ShareLink(item: send.shareURL) { Label("共享…", systemImage: "square.and.arrow.up") }
                }
                .padding(.top, Spacing.sm)
            }
            .padding(Spacing.lg)
        }
        #else
        card {
            copyField(title: "共享链接", value: send.shareURL.absoluteString, isLink: true)
            if !isSheet {
                Divider()
                contentField
            }
        }
        #endif
        card {
            #if os(macOS)
            contentField
            Divider()
            #endif
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
            let layout = dynamicTypeSize.isAccessibilitySize ? AnyLayout(VStackLayout()) : AnyLayout(HStackLayout())
            layout {
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

    @ViewBuilder private var contentField: some View {
        if send.kind == .text, let text = send.text { copyField(title: "文本", value: text) }
        else if let name = send.fileName { copyField(title: "文件名", value: name) }
    }

    private var rowHeight: CGFloat {
        #if os(macOS)
        38
        #else
        52
        #endif
    }

    private func card<Content: View>(@ViewBuilder content: @escaping () -> Content) -> some View {
        #if os(macOS)
        MacDetailCard { VStack(alignment: .leading, spacing: 0, content: content) }
        #else
        OpenVaultCard(cornerRadius: isSheet ? CornerRadius.iPhoneCard : CornerRadius.iPadCard, padding: 0) {
            VStack(alignment: .leading, spacing: 0, content: content)
        }
        #endif
    }

    private func info(_ title: String, _ value: String) -> some View {
        #if os(macOS)
        MacDetailRow(title, alignment: .top, minimumHeight: LayoutMetric.desktopRowHeight) { Text(value) }
        #else
        LabeledContent(title) { Text(value).multilineTextAlignment(.trailing) }
            .padding(.horizontal, 14).padding(.vertical, 4)
            .frame(minHeight: rowHeight)
        #endif
    }

    private func copyField(title: String, value: String, isLink: Bool = false) -> some View {
        InlineCopyButton(action: { SendClipboard.copy(value) }) { copied in
            #if os(macOS)
            MacDetailRow(title, alignment: .top, minimumHeight: LayoutMetric.desktopRowHeight) {
                HStack {
                    Text(value)
                    Spacer(minLength: 0)
                    if copied { InlineCopyIndicator() }
                }
            }
            #else
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(.footnote).foregroundStyle(.secondary)
                    Text(value).font(isLink ? .system(.subheadline, design: .monospaced) : .body)
                        .lineLimit(isLink && !dynamicTypeSize.isAccessibilitySize ? 1 : nil)
                        .truncationMode(.middle)
                }
                Spacer()
                if copied { InlineCopyIndicator() }
            }
            .padding(.horizontal, 14).padding(.vertical, 8)
            .frame(minHeight: isLink ? 64 : rowHeight).contentShape(.rect)
            #endif
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
