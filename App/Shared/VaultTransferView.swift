import CryptoCore
import DesignSystem
import Foundation
import SwiftUI
import Synchronization
import UIShared
import UniformTypeIdentifiers
import VaultRepository

enum VaultTransferMode: Hashable { case importItems, exportItems }

private enum TransferSource: String, CaseIterable {
    case apple = "Apple 密码（CSV）"
    case bitwarden = "Bitwarden（JSON）"
    case bitwardenCSV = "Bitwarden（CSV）"
    case browser = "Chrome 或 Edge（CSV）"
    case onePassword = "1Password（1PUX）"

    var contentType: UTType {
        switch self {
        case .bitwarden: .json
        case .onePassword: UTType(filenameExtension: "1pux") ?? .data
        default: .commaSeparatedText
        }
    }

    var fileFormat: VaultTransferImportFormat {
        switch self {
        case .apple: .csv(.apple)
        case .bitwarden: .bitwardenJSON
        case .bitwardenCSV: .csv(.bitwarden)
        case .browser: .csv(.browser)
        case .onePassword: .onePassword
        }
    }

    var description: String {
        switch self {
        case .apple: "包含网站、用户名、密码、备注和验证码密钥。"
        case .bitwarden: "支持五种个人条目和文件夹；加密 JSON 需要文件密码。回收站条目不会导入。"
        case .bitwardenCSV: "仅包含登录和安全笔记。CSV 不保留通行密钥或自定义字段类型。"
        case .browser: "包含网站、用户名、密码和文件中的备注。"
        case .onePassword: "导入单账户个人库中的登录、密码、笔记、银行卡和身份。共享库、归档、附件或无法保留的字段将阻止导入。"
        }
    }
}

private enum TransferFormat: String, CaseIterable {
    case json = "JSON"
    case encrypted = "加密 JSON（文件密码）"
    case csv = "CSV"

    var contentType: UTType { self == .csv ? .commaSeparatedText : .json }

    var fileFormat: VaultTransferExportFormat {
        switch self {
        case .json: .json
        case .encrypted: .encryptedJSON
        case .csv: .csv
        }
    }
}

struct VaultTransferView: View {
    let auth: AuthService
    let vault: VaultService
    let personalItemCount: Int?
    let onImported: () async -> Void

    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @State private var mode: VaultTransferMode
    @State private var source = TransferSource.apple
    @State private var format = TransferFormat.json
    @State private var folders: [PlaintextFolder] = []
    @State private var accountEmail: String?
    @State private var folderID: String?
    @State private var lease: AccountSessionLease?
    @State private var selectedURL: URL?
    @State private var protectedInput: Data?
    @State private var masterPassword = ""
    @State private var filePassword = ""
    @State private var confirmation = ""
    @State private var picking = false
    @State private var exporting = false
    @State private var document: TransferDocument?
    @State private var operation: Task<Void, Never>?
    @State private var feedback: String?
    @State private var progress = false

    init(mode: VaultTransferMode = .importItems, auth: AuthService, vault: VaultService, personalItemCount: Int? = nil,
         onImported: @escaping () async -> Void = {}) {
        _mode = State(initialValue: mode)
        self.auth = auth
        self.vault = vault
        self.personalItemCount = personalItemCount
        self.onImported = onImported
    }

    var body: some View {
        platformForm
            .task { await loadContext() }
            .onChange(of: mode) { _, _ in resetFields() }
            .onChange(of: format) { _, _ in resetFields() }
            .onChange(of: source) { _, _ in resetFields() }
            .onChange(of: scenePhase) { _, phase in
                if phase == .background { cancelTransfer() }
            }
            .onDisappear { cancelTransfer() }
            .fileImporter(isPresented: $picking, allowedContentTypes: [source.contentType]) { result in
                switch result {
                case .success(let url):
                    selectedURL = url
                    protectedInput = nil
                    filePassword = ""
                    feedback = nil
                    #if os(iOS)
                    start { try await importSelection() }
                    #endif
                case .failure(let error): if !Self.isCancellation(error) { feedback = "无法打开所选文件。" }
                }
            }
            .fileExporter(isPresented: $exporting, document: document, contentTypes: [format.contentType],
                          defaultFilename: "OpenVault", onCompletion: { result in
                clearDocument()
                switch result {
                case .success: feedback = "保险库已导出。"
                case .failure(let error): if !Self.isCancellation(error) { feedback = "无法保存导出文件。" }
                }
            }, onCancellation: { clearDocument() })
    }

    @ViewBuilder private var platformForm: some View {
        #if os(macOS)
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: Spacing.xs) {
                Text(mode == .importItems ? "导入条目" : "导出保险库").font(.headline).accessibilityAddTraits(.isHeader)
                if mode == .exportItems, let accountEmail {
                    Group {
                        if let personalItemCount {
                            Text("\(accountEmail) 的个人保险库，共 \(personalItemCount) 个条目、\(folders.count) 个文件夹。")
                        } else {
                            Text("\(accountEmail) 的个人保险库")
                        }
                    }
                    .font(.subheadline).foregroundStyle(.secondary)
                }
            }
            .privacySensitive()
            .padding(.horizontal, Spacing.xl)
            .padding(.top, 22)
            Form { sections }.formStyle(.grouped).scrollContentBackground(.hidden)
            HStack {
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                actionButton.keyboardShortcut(.defaultAction)
            }
            .padding(.horizontal, Spacing.xl)
            .padding(.bottom, 20)
        }
        .frame(width: 560, height: mode == .importItems ? (protectedInput != nil || feedback != nil ? 400 : 340) : 500)
        #else
        Form {
            Picker("导入或导出", selection: $mode) {
                Text("导入").tag(VaultTransferMode.importItems)
                Text("导出").tag(VaultTransferMode.exportItems)
            }
            .pickerStyle(.segmented).labelsHidden()
            .listRowInsets(EdgeInsets())
            .listRowBackground(Color.clear)
            .disabled(progress)
            sections
            actionButton.listRowInsets(EdgeInsets()).listRowBackground(Color.clear)
        }
        .listSectionSpacing(Spacing.lg)
        .navigationTitle("导入与导出")
        #endif
    }

    @ViewBuilder private var sections: some View {
        if mode == .importItems {
            Section {
                Picker("来源", selection: $source) {
                    ForEach(TransferSource.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }
                #if os(macOS)
                LabeledContent("文件") {
                    Text(selectedURL?.lastPathComponent ?? "未选择").foregroundStyle(.secondary).lineLimit(1)
                    Button("选择文件…") { picking = true }
                }
                #endif
                Picker("放入文件夹", selection: $folderID) {
                    Text("保持原有文件夹").tag(String?.none)
                    ForEach(folders) { Text($0.name).tag(Optional($0.id)) }
                }
                if protectedInput != nil { passwordField("文件密码", value: $filePassword, prompt: "输入导出时设置的密码") }
            } footer: { Text(source.description + " 重复的条目不会自动合并。") }
            .disabled(progress)
        } else {
            Section {
                Picker("格式", selection: $format) {
                    ForEach(TransferFormat.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }
                if format == .encrypted {
                    passwordField("文件密码", value: $filePassword, prompt: "设置文件密码")
                    passwordField("确认文件密码", value: $confirmation, prompt: "再次输入文件密码")
                }
            } footer: {
                Text(format == .csv ? "CSV 仅导出登录和安全笔记，不保留通行密钥、字段类型或网站匹配规则。" : "包含个人条目（包括通行密钥、SSH 私钥）和文件夹。归档条目会作为普通条目导出，不包含密码历史。")
            }
            .disabled(progress)
            if format != .encrypted {
                Section {
                    HStack(alignment: .firstTextBaseline, spacing: Spacing.sm) {
                        Image(systemName: "exclamationmark.triangle")
                            .foregroundStyle(Palette.warning)
                            .accessibilityHidden(true)
                        Text("\(Text("文件未加密。").fontWeight(.semibold))拿到文件的人可以读取其中的密码。请勿用电子表格打开，用完请立即删除。")
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .font(.body)
                    .padding(Spacing.xs)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityElement(children: .combine)
                }
            }
            Section {
                passwordField("主密码", value: $masterPassword, prompt: "再次输入以确认").textContentType(.password)
            } footer: { Text("附件、Send 和回收站中的条目不会导出。") }
            .disabled(progress)
        }
        if let feedback { Section { Text(feedback).font(.callout) } }
        if progress { ProgressView(mode == .importItems ? "正在导入…" : "正在准备导出…") }
    }

    private func passwordField(_ title: LocalizedStringKey, value: Binding<String>, prompt: LocalizedStringKey) -> some View {
        LabeledContent(title) {
            SecureField(title, text: value, prompt: Text(prompt)).labelsHidden().multilineTextAlignment(.trailing)
        }
    }

    private var actionButton: some View {
        Button {
            if mode == .exportItems { start { try await prepareExport() }; return }
            #if os(iOS)
            if protectedInput == nil { picking = true; return }
            #endif
            start { try await importSelection() }
        } label: {
            #if os(iOS)
            Text(actionTitle).frame(maxWidth: .infinity, minHeight: 40)
            #else
            Text(actionTitle)
            #endif
        }
        .vaultProminentButtonStyle()
        #if os(iOS)
        .buttonBorderShape(.capsule)
        #endif
        .disabled(!canSubmit)
    }

    private var actionTitle: String {
        if mode == .exportItems { return "导出…" }
        if protectedInput != nil { return "解密并导入" }
        #if os(macOS)
        return "导入"
        #else
        return "选择文件并导入…"
        #endif
    }

    private var canSubmit: Bool {
        guard lease != nil, !progress else { return false }
        if mode == .exportItems {
            return !masterPassword.isEmpty && (format != .encrypted || (!filePassword.isEmpty && filePassword == confirmation))
        }
        if protectedInput != nil { return !filePassword.isEmpty }
        #if os(macOS)
        return selectedURL != nil
        #else
        return true
        #endif
    }

    private func loadContext() async {
        guard let active = await auth.transferSession() else { feedback = "请先解锁保险库。"; return }
        do {
            let available = try await vault.folders()
            let email = await auth.accountEmail()
            guard await auth.transferSession() == active, !Task.isCancelled else { return }
            folders = available
            accountEmail = email
            lease = active
        } catch { feedback = "无法读取保险库。请返回后重试。" }
    }

    private func start(_ action: @escaping @MainActor () async throws -> Void) {
        guard !progress else { return }
        progress = true
        feedback = nil
        operation = Task {
            defer { progress = false; operation = nil }
            do { try await action() }
            catch {
                guard !Task.isCancelled else { return }
                feedback = Self.message(for: error)
                if let failure = error as? VaultTransferError, case .partialImport = failure { await onImported() }
            }
        }
    }

    private func importSelection() async throws {
        guard let lease, await auth.transferSession() == lease, let selectedURL else { throw RepositoryError.locked }
        let data: Data
        if let protectedInput { data = protectedInput }
        else { data = try await VaultTransferFiles.read(selectedURL) }
        try Task.checkCancellation()
        if source == .bitwarden, filePassword.isEmpty, try await VaultTransferFiles.isEncrypted(data) {
            protectedInput = data
            feedback = "请输入此文件的导出密码。"
            return
        }
        let password = filePassword
        filePassword = ""
        let archive = try await VaultTransferFiles.decode(data, format: source.fileFormat, password: password)
        try Task.checkCancellation()
        guard await auth.transferSession() == lease else { throw RepositoryError.locked }
        protectedInput = nil
        let count = try await VaultTransferWriter.persist(archive, to: folderID, existingFolders: folders,
                                                         vault: vault, lease: lease)
        try Task.checkCancellation()
        self.selectedURL = nil
        feedback = "已导入 \(count) 个条目。"
        await onImported()
        await loadContext()
    }

    private func prepareExport() async throws {
        guard let lease else { throw RepositoryError.locked }
        let password = masterPassword
        let encryptionPassword = filePassword
        masterPassword = ""
        filePassword = ""
        confirmation = ""
        let output = try await VaultTransferFiles.prepareExport(format: format.fileFormat, filePassword: encryptionPassword,
                                                               masterPassword: password, auth: auth, vault: vault, lease: lease)
        try Task.checkCancellation()
        document = TransferDocument(output)
        exporting = true
    }

    private func clearDocument() { document?.clear(); document = nil }

    private func resetFields() {
        clearDocument()
        feedback = nil
        protectedInput = nil
        selectedURL = nil
        masterPassword = ""
        filePassword = ""
        confirmation = ""
    }

    private func cancelTransfer() {
        operation?.cancel()
        exporting = false
        resetFields()
    }

    private static func isCancellation(_ error: Error) -> Bool {
        (error as NSError).domain == NSCocoaErrorDomain && (error as NSError).code == NSUserCancelledError
    }

    private static func message(for error: Error) -> String {
        if let crypto = error as? PasswordProtectedExportError {
            switch crypto {
            case .emptyPassword: return "文件密码不能只包含空白字符。"
            case .authenticationFailed: return "文件密码不正确或文件已损坏。"
            case .unsupportedKDF, .unsupportedIterations: return "此文件的密钥派生设置不受支持。"
            case .unsupportedFormat: return "仅支持使用文件密码的加密 JSON，不支持账户绑定的备份。"
            default: return "加密文件无效或超出支持的大小。"
            }
        }
        if let repo = error as? RepositoryError {
            switch repo {
            case .authenticationFailed: return "主密码不正确。"
            case .notAuthenticated, .locked: return "保险库已锁定或账户已更改。"
            default: return "无法读取或写入保险库。请检查连接后重试。"
            }
        }
        if let failure = error as? VaultTransferError {
            switch failure {
            case .emptyFile: return "文件中没有可导入的条目或文件夹。"
            case .emptyExport: return "没有可用此格式导出的内容。"
            case .unrepresentableCSV: return "部分自定义字段或网站地址无法用 CSV 完整保存。请改用 JSON。"
            case .fileTooLarge: return "文件过大或条目过多。请分批导入。"
            case .unsupportedFile: return "文件不属于所选来源，或使用了不支持的格式。"
            case .unsupportedItem: return "文件含不支持的类型、历史记录、附件或无法保留的字段，未进行导入。"
            case .partialImport(let items, let folders): return "导入已中断。已写入 \(items) 个条目、\(folders) 个文件夹；重复导入不会自动合并。"
            default: return "无法读取文件。请检查格式和内容后重试。"
            }
        }
        return "操作失败。请检查文件、格式和保险库后重试。"
    }
}

private final class TransferDocument: FileDocument {
    static let readableContentTypes = [UTType.json, .commaSeparatedText]
    private let bytes: Mutex<Data?>

    init(_ data: Data) { bytes = Mutex(data) }
    init(configuration: ReadConfiguration) throws { throw CocoaError(.fileReadCorruptFile) }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        try bytes.withLock { data in
            guard let data else { throw CocoaError(.userCancelled) }
            return FileWrapper(regularFileWithContents: data)
        }
    }

    func clear() { bytes.withLock { $0 = nil } }
}
