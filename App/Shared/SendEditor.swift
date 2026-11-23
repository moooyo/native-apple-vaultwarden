import SwiftUI
import DesignSystem
import UniformTypeIdentifiers
import VaultRepository

private enum SendLifetime: CaseIterable, Hashable {
    case never, hour, day, twoDays, threeDays, week, month, custom

    var title: LocalizedStringKey {
        switch self {
        case .never: "不过期"
        case .hour: "1 小时后"
        case .day: "1 天后"
        case .twoDays: "2 天后"
        case .threeDays: "3 天后"
        case .week: "7 天后"
        case .month: "30 天后"
        case .custom: "自定义…"
        }
    }

    func date(from now: Date, custom: Date) -> Date? {
        switch self {
        case .never: nil
        case .hour: now.addingTimeInterval(3600)
        case .day: now.addingTimeInterval(86_400)
        case .twoDays: now.addingTimeInterval(2 * 86_400)
        case .threeDays: now.addingTimeInterval(3 * 86_400)
        case .week: now.addingTimeInterval(7 * 86_400)
        case .month: now.addingTimeInterval(30 * 86_400)
        case .custom: custom
        }
    }
}

extension VaultSendDraft {
    init(editing send: VaultSend) {
        self.init(kind: send.kind, name: send.name, text: send.text ?? "", hideText: send.hideText,
                  deletionDate: send.deletionDate, expirationDate: send.expirationDate,
                  maxAccessCount: send.maxAccessCount, hideEmail: send.hideEmail,
                  disabled: send.disabled, notes: send.notes)
    }
}

enum SendFailure {
    static func message(for error: Error) -> String {
        guard let error = error as? VaultSendError else { return "无法完成操作，请检查网络后重试。" }
        switch error {
        case .invalidDraft: return "请检查名称、内容、日期和访问限制。"
        case .textTooLong: return "文本超过 Send 长度限制。请缩短文本或改用文件。"
        case .fileTooLarge: return "文件不能超过 500 MiB。"
        case .unsupportedUpload: return "当前服务器不支持此文件上传方式。"
        case .unsupportedFormat: return "此 Send 的格式暂不受支持。"
        case .invalidLink: return "服务器未返回有效的共享链接。"
        }
    }
}

struct SendEditor: View {
    let service: (any VaultSendService)?
    let item: VaultSend?
    let onSaved: (VaultSend) -> Void

    @Environment(\.dismiss) private var dismiss
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @State private var draft: VaultSendDraft
    @State private var deletion: SendLifetime
    @State private var expiration: SendLifetime
    @State private var customExpiration: Date
    @State private var maxAccess: String
    @State private var password = ""
    @State private var note: String
    @State private var choosingFile = false
    @State private var confirmingPasswordRemoval = false
    @State private var failure: String?
    @State private var isSaving = false
    @State private var saveTask: Task<Void, Never>?
    #if os(iOS)
    @FocusState private var focusedField: Field?

    private enum Field { case name, text, maxAccess, password, note }
    #endif

    init(service: (any VaultSendService)?, item: VaultSend? = nil, onSaved: @escaping (VaultSend) -> Void) {
        self.service = service
        self.item = item
        self.onSaved = onSaved
        let initial = item.map { VaultSendDraft(editing: $0) } ?? VaultSendDraft(
            kind: .text, name: "", hideText: true, deletionDate: Date.now.addingTimeInterval(7 * 86_400), hideEmail: true
        )
        _draft = State(initialValue: initial)
        _deletion = State(initialValue: item == nil ? .week : .custom)
        _expiration = State(initialValue: initial.expirationDate == nil ? .never : .custom)
        _customExpiration = State(initialValue: initial.expirationDate ?? Date.now.addingTimeInterval(86_400))
        _maxAccess = State(initialValue: initial.maxAccessCount.map { String($0) } ?? "")
        _note = State(initialValue: initial.notes ?? "")
    }

    private var title: LocalizedStringKey { item == nil ? "新建 Send" : "编辑 Send" }
    private var submitTitle: LocalizedStringKey { item == nil ? "创建并拷贝链接" : "存储" }

    private func preparedDraft(at now: Date) -> VaultSendDraft? {
        var value = draft
        value.name = value.name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.name.isEmpty,
              let deletionDate = deletion.date(from: now, custom: value.deletionDate),
              deletionDate > now, deletionDate <= now.addingTimeInterval(31 * 86_400) else { return nil }
        value.deletionDate = deletionDate
        value.expirationDate = expiration.date(from: now, custom: customExpiration)
        if let expires = value.expirationDate, expires > deletionDate { return nil }
        if value.kind == .text {
            guard !value.text.isEmpty else { return nil }
            value.fileURL = nil
        } else {
            guard item != nil || value.fileURL != nil else { return nil }
            value.text = ""
        }
        let limit = maxAccess.trimmingCharacters(in: .whitespaces)
        if limit.isEmpty {
            value.maxAccessCount = nil
        } else {
            guard let count = Int(limit), (1...Int(Int32.max)).contains(count) else { return nil }
            value.maxAccessCount = count
        }
        value.password = password.isEmpty || value.removePassword ? nil : password
        value.notes = note.isEmpty ? nil : note
        return value
    }

    var body: some View {
        Group {
            #if os(macOS)
            VStack(spacing: 0) {
                HStack {
                    Text(title).font(.headline).accessibilityAddTraits(.isHeader)
                    Spacer()
                    kindPicker.frame(width: 160)
                }
                .padding([.top, .horizontal], 24)
                fields
                Divider()
                HStack {
                    Spacer()
                    cancelButton.keyboardShortcut(.cancelAction)
                    submitButton.keyboardShortcut(.defaultAction)
                }
                .padding()
            }
            .frame(width: 600, height: 600)
            #else
            NavigationStack {
                fields
                    .navigationTitle(title)
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) { cancelButton }
                        ToolbarItem(placement: .confirmationAction) { submitButton }
                    }
            }
            .presentationSizing(.form)
            .presentationDragIndicator(.visible)
            #endif
        }
        .interactiveDismissDisabled(isSaving)
        .onDisappear { saveTask?.cancel() }
        .fileImporter(isPresented: $choosingFile, allowedContentTypes: [.data]) { result in
            switch result {
            case .success(let url):
                draft.fileURL = url
                if draft.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    draft.name = url.lastPathComponent
                }
            case .failure(let error):
                if (error as? CocoaError)?.code != .userCancelled { failure = "无法选择文件，请重试。" }
            }
        }
        .alert("无法完成操作", isPresented: Binding(get: { failure != nil }, set: { if !$0 { failure = nil } })) {
            Button("好", role: .cancel) { failure = nil }
        } message: { Text(LocalizedStringKey(failure ?? "")) }
        .confirmationDialog("移除访问密码？", isPresented: $confirmingPasswordRemoval, titleVisibility: .visible) {
            Button("移除密码", role: .destructive) { password = ""; draft.removePassword = true }
            Button("取消", role: .cancel) {}
        } message: { Text("存储后，任何持有有效链接的人都将不再需要密码即可访问。") }
    }

    private var fields: some View {
        Form {
            #if os(iOS)
            Section { kindPicker.listRowInsets(EdgeInsets()).listRowBackground(Color.clear) }
            #endif
            Section {
                field("名称") {
                    TextField("名称", text: $draft.name, prompt: Text("必填，只有你能看到"))
                        .accessibilityIdentifier("send.name")
                        #if os(iOS)
                        .focused($focusedField, equals: .name)
                        #endif
                }
                if draft.kind == .text {
                    field("文本", multiline: true) {
                        TextEditor(text: $draft.text)
                            .scrollContentBackground(.hidden)
                            .frame(minHeight: 60)
                            .accessibilityLabel("文本")
                            .accessibilityIdentifier("send.text")
                            .privacySensitive()
                            .autocorrectionDisabled()
                            #if os(iOS)
                            .focused($focusedField, equals: .text)
                            #endif
                    }
                    Toggle("默认隐藏文本", isOn: $draft.hideText)
                } else {
                    if let filename = item?.fileName ?? draft.fileURL?.lastPathComponent {
                        LabeledContent("文件", value: filename).privacySensitive()
                    }
                    if item == nil {
                        Button(draft.fileURL == nil ? "选择文件…" : "选择其他文件…") { choosingFile = true }
                    }
                }
            }
            Section {
                Picker("删除时间", selection: $deletion) {
                    ForEach(SendLifetime.allCases.filter { $0 != .never }, id: \.self) { Text($0.title).tag($0) }
                }
                if deletion == .custom {
                    DatePicker("删除日期", selection: $draft.deletionDate)
                }
                Picker("过期时间", selection: $expiration) {
                    ForEach([SendLifetime.never, .hour, .day, .week, .custom], id: \.self) { Text($0.title).tag($0) }
                }
                if expiration == .custom { DatePicker("过期日期", selection: $customExpiration) }
                if let warning = dateWarning { Text(warning).font(.footnote).foregroundStyle(.red) }
            } header: {
                #if os(iOS)
                Text("有效期")
                #endif
            }
            Section {
                field("最大访问次数") {
                    TextField("最大访问次数", text: $maxAccess, prompt: Text("不限"))
                        #if os(iOS)
                        .keyboardType(.numberPad)
                        .focused($focusedField, equals: .maxAccess)
                        #endif
                }
                if draft.removePassword {
                    LabeledContent("访问密码") {
                        Button("撤销移除密码") { draft.removePassword = false }
                    }
                } else {
                    field("访问密码") {
                        SecureField("访问密码", text: $password,
                                    prompt: Text(item?.hasPassword == true ? "留空以保留现有密码" : "可选"))
                            .textContentType(.newPassword)
                            #if os(iOS)
                            .focused($focusedField, equals: .password)
                            #endif
                    }
                    if item?.hasPassword == true {
                        Button("移除访问密码…", role: .destructive) { confirmingPasswordRemoval = true }
                    }
                }
                Toggle("隐藏我的邮箱", isOn: $draft.hideEmail)
                if item != nil { Toggle("停用此 Send", isOn: $draft.disabled) }
            } header: {
                #if os(iOS)
                Text("访问")
                #endif
            }
            Section {
                field("私人备注", multiline: true) {
                    TextField("私人备注", text: $note, prompt: Text("接收者看不到"), axis: .vertical)
                        .lineLimit(2...4).privacySensitive()
                        #if os(iOS)
                        .focused($focusedField, equals: .note)
                        #endif
                }
            }
            if service == nil { Text("当前无法连接 Send 服务。").font(.footnote).foregroundStyle(.secondary) }
        }
        .formStyle(.grouped)
        #if os(macOS)
        .toggleStyle(.checkbox)
        .scrollContentBackground(.hidden)
        .disabled(isSaving)
        #else
        .listSectionSpacing(Spacing.lg)
        .contentMargins(.top, Spacing.md, for: .scrollContent)
        .allowsHitTesting(!isSaving)
        .accessibilityHidden(isSaving)
        #endif
    }

    @ViewBuilder private func field<Content: View>(_ title: LocalizedStringKey, multiline: Bool = false,
                                                  @ViewBuilder input: () -> Content) -> some View {
        let stackVertically = dynamicTypeSize.isAccessibilitySize
        #if os(macOS)
        let stacked = stackVertically || multiline
        #else
        let stacked = stackVertically
        #endif
        if stacked {
            VStack(alignment: .leading, spacing: Spacing.xs) {
                Text(title)
                input().labelsHidden()
            }
        } else {
            HStack(alignment: multiline ? .top : .center, spacing: Spacing.md) {
                Text(title).fixedSize(horizontal: true, vertical: false)
                    #if os(iOS)
                    .frame(minWidth: 84, alignment: .leading)
                    #endif
                input().labelsHidden()
                    .multilineTextAlignment(multiline ? .leading : .trailing)
                    .frame(maxWidth: .infinity)
            }
        }
    }

    private var dateWarning: LocalizedStringKey? {
        let now = Date.now
        guard let removal = deletion.date(from: now, custom: draft.deletionDate) else { return nil }
        if removal <= now || removal > now.addingTimeInterval(31 * 86_400) {
            return "删除日期须在未来 31 天以内。"
        }
        if let expiry = expiration.date(from: now, custom: customExpiration), expiry > removal {
            return "过期时间不能晚于删除时间。"
        }
        return nil
    }

    private var kindPicker: some View {
        Group {
            #if os(macOS)
            MacSegmentedPicker(MacLocalization.text("Send 类型"), options: [.text, .file], selection: $draft.kind) {
                MacLocalization.text($0 == .text ? "文本" : "文件")
            }
            #else
            Picker("Send 类型", selection: $draft.kind) {
                Text("文本").tag(VaultSendKind.text)
                Text("文件").tag(VaultSendKind.file)
            }
            .pickerStyle(.segmented).labelsHidden()
            #endif
        }
        .accessibilityIdentifier("send.kind")
        .disabled(item != nil || isSaving)
    }

    private var cancelButton: some View {
        Button(action: { dismiss() }) {
            #if os(macOS)
            Text("取消")
            #else
            Label("取消", systemImage: "xmark").labelStyle(.iconOnly)
            #endif
        }
        .disabled(isSaving)
        .accessibilityIdentifier("send.cancel")
    }

    private var submitButton: some View {
        Button(action: save) {
            if isSaving { ProgressView().controlSize(.small) }
            else {
                #if os(macOS)
                Text(submitTitle)
                #else
                Label(submitTitle, systemImage: "checkmark").labelStyle(.iconOnly)
                #endif
            }
        }
        #if os(iOS)
        .vaultProminentButtonStyle(glass: true)
        .buttonBorderShape(.circle)
        #endif
        .disabled(service == nil || isSaving || preparedDraft(at: .now) == nil)
        .accessibilityLabel(isSaving ? "正在存储" : submitTitle)
        .accessibilityIdentifier("send.create")
    }

    private func save() {
        guard let service, !isSaving, let value = preparedDraft(at: .now) else { return }
        #if os(iOS)
        focusedField = nil
        #endif
        isSaving = true
        saveTask = Task { @MainActor in
            defer { isSaving = false }
            do {
                let saved: VaultSend
                if let item { saved = try await service.updateSend(id: item.id, draft: value) }
                else { saved = try await service.createSend(value) }
                guard !Task.isCancelled else { return }
                onSaved(saved)
                dismiss()
            } catch {
                if !Task.isCancelled { failure = SendFailure.message(for: error) }
            }
        }
    }
}
