import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels
import Generators

@available(iOS 27.0, *)
public struct ItemEditView: View {
    private let vault: VaultService
    private let existing: PlaintextCipher?
    private let requiresCode: Bool
    private let onCancel: (() -> Void)?
    private let onTrash: (() -> Void)?
    private let onSaved: (String) -> Void

    @Environment(\.dismiss) private var dismiss
    @Environment(\.horizontalSizeClass) private var sizeClass
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor
    @State private var original: PlaintextCipher?
    @State private var draft: PlaintextCipher
    @State private var login: PlaintextCipher.Login
    @State private var card: PlaintextCipher.Card
    @State private var identity: PlaintextCipher.Identity
    @State private var ssh: PlaintextCipher.SshKey
    @State private var sites: [SiteDraft]
    @State private var folders: [PlaintextFolder] = []
    @State private var folderLoadFailed = false
    @State private var isSaving = false
    @State private var errorMessage: String?

    public init(vault: VaultService, existing: PlaintextCipher? = nil, initialFolderID: String? = nil,
                initialType: CipherType = .login, initiallyFavorite: Bool = false, requiresCode: Bool = false,
                onCancel: (() -> Void)? = nil, onTrash: (() -> Void)? = nil,
                onSaved: @escaping (String) -> Void) {
        self.vault = vault
        self.existing = existing
        self.requiresCode = requiresCode
        self.onCancel = onCancel
        self.onTrash = onTrash
        self.onSaved = onSaved
        let initial = existing ?? PlaintextCipher(type: initialType.rawValue, name: "", folderID: initialFolderID,
                                                  favorite: initiallyFavorite)
        _original = State(initialValue: existing)
        _draft = State(initialValue: initial)
        _login = State(initialValue: initial.login ?? .init())
        _card = State(initialValue: initial.card ?? .init())
        _identity = State(initialValue: initial.identity ?? .init())
        _ssh = State(initialValue: initial.sshKey ?? .init())
        let initialSites = (initial.login?.uris ?? []).map { SiteDraft(value: $0) }
        _sites = State(initialValue: initialSites.isEmpty ? [SiteDraft()] : initialSites)
    }

    private var kind: CipherType { CipherType(rawValue: draft.type) }
    private var isSSHKeyIncomplete: Bool { kind == .sshKey && !ssh.isComplete }

    private var codeError: String? {
        guard kind == .login else { return nil }
        let raw = login.totp ?? ""
        if raw.isEmpty { return requiresCode ? "请输入验证器密钥或 otpauth:// 链接。" : nil }
        if raw == original?.login?.totp, !requiresCode { return nil }
        return (try? TOTP.configuration(from: raw)) == nil ? "验证器密钥无效，请检查输入。" : nil
    }

    private var canSave: Bool {
        if case .unknown = kind { return false }
        return !draft.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && codeError == nil && !isSSHKeyIncomplete && !isSaving
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.lg) {
                if let existing {
                    editHeader(existing)
                } else if !requiresCode { typePicker }

                group {
                    if existing == nil || sizeClass != .regular { input("名称", $draft.name, prompt: "必填"); divider }
                    folderPicker
                }
                switch kind {
                case .login: loginFields
                case .card: cardFields
                case .identity: identityFields
                case .sshKey: sshFields
                case .secureNote: notesField
                case .unknown: EmptyView()
                }
                group {
                    Toggle("置顶", isOn: $draft.favorite)
                        .padding(.horizontal, Spacing.lg).frame(minHeight: LayoutMetric.phoneRowHeight)
                    if kind != .secureNote {
                        divider
                        input("备注", $draft.notes.editText, prompt: "添加备注…", multiline: true)
                    }
                }
                if let onTrash {
                    group {
                        Button(role: .destructive, action: onTrash) {
                            Text("移到回收站").frame(maxWidth: .infinity, minHeight: LayoutMetric.phoneRowHeight)
                        }
                    }
                }
            }
            .frame(maxWidth: existing == nil && sizeClass == .regular ? 580 : LayoutMetric.padDetailWidth)
            .padding(Spacing.lg)
            .frame(maxWidth: .infinity)
        }
        .scrollDismissesKeyboard(.interactively)
        .background(Palette.groupedBackground)
        .navigationTitle(existing == nil ? "新建\(kind.editorTitle)" : "")
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(onCancel != nil)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button {
                    if let onCancel { onCancel() } else { dismiss() }
                } label: {
                    if existing == nil { Label("取消", systemImage: "xmark").labelStyle(.iconOnly) }
                    else { Text("取消") }
                }
                .accessibilityIdentifier("item.cancel")
            }
            ToolbarItem(placement: .confirmationAction) {
                if isSaving { ProgressView() }
                else {
                    Button(existing == nil ? "存储" : "完成", systemImage: "checkmark", action: save)
                        .labelStyle(.iconOnly)
                        .buttonStyle(.glassProminent)
                        .disabled(!canSave)
                        .accessibilityIdentifier("item.save")
                }
            }
        }
        .disabled(isSaving)
        .interactiveDismissDisabled(isSaving)
        .task { await loadFolders() }
        .alert("无法完成操作", isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(errorMessage ?? "") }
    }

    private func editHeader(_ existing: PlaintextCipher) -> some View {
        let wide = sizeClass == .regular
        let layout = wide ? AnyLayout(HStackLayout(spacing: Spacing.lg)) : AnyLayout(VStackLayout(spacing: Spacing.sm))
        return layout {
            BrandBadge(existing, diameter: 64)
            VStack(alignment: wide ? .leading : .center, spacing: Spacing.xs) {
                if wide { TextField("名称", text: $draft.name).font(.title.bold()) }
                else { Text(existing.openVaultName).font(.title2.bold()) }
                Text(existing.openVaultKindLabel).font(.footnote).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: wide ? .leading : .center)
    }

    private var typePicker: some View {
        let columns = Array(repeating: GridItem(.flexible(), spacing: Spacing.xs), count: dynamicTypeSize.isAccessibilitySize ? 2 : 5)
        return LazyVGrid(columns: columns, spacing: Spacing.sm) {
            ForEach([CipherType.login, .card, .identity, .secureNote, .sshKey], id: \.rawValue) { option in
                let selected = option == kind
                Button { draft.type = option.rawValue } label: {
                    VStack(spacing: Spacing.xs) {
                        Image(systemName: option.editorSymbol)
                            .font(.title3.weight(.medium)).frame(width: 48, height: 48)
                            .foregroundStyle(selected ? (colorScheme == .dark && contrast == .increased ? Color.black : .white) : Palette.accent)
                            .background(selected ? Palette.accent : Palette.contentBackground,
                                        in: RoundedRectangle(cornerRadius: CornerRadius.button))
                            .overlay(alignment: .topTrailing) {
                                if selected, differentiateWithoutColor {
                                    Image(systemName: "checkmark.circle.fill")
                                        .font(.caption).symbolRenderingMode(.palette)
                                        .foregroundStyle(Palette.contentBackground, Palette.primaryText)
                                        .accessibilityHidden(true)
                                }
                            }
                        Text(option.editorLabel).font(.caption.weight(.semibold))
                            .foregroundStyle(selected ? Palette.primaryText : Palette.secondaryText)
                            .multilineTextAlignment(.center)
                    }
                }
                .buttonStyle(.plain)
                .accessibilityLabel(option.editorLabel)
                .accessibilityAddTraits(selected ? .isSelected : [])
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("条目类型")
    }

    @ViewBuilder private var folderPicker: some View {
        if folderLoadFailed {
            Button { Task { await loadFolders() } } label: {
                LabeledContent("文件夹", value: "无法载入，重试")
                    .padding(.horizontal, Spacing.lg).frame(minHeight: LayoutMetric.phoneRowHeight)
            }
        } else {
            editorRow("文件夹") {
                Picker("文件夹", selection: $draft.folderID) {
                    Text("无文件夹").tag(nil as String?)
                    if let id = draft.folderID, !folders.contains(where: { $0.id == id }) {
                        Text("当前文件夹").tag(Optional(id))
                    }
                    ForEach(folders, id: \.id) { folder in Text(folder.name).tag(Optional(folder.id)) }
                }
                .labelsHidden().pickerStyle(.menu).accessibilityLabel("文件夹")
            }
        }
    }

    private func loadFolders() async {
        do { folders = try await vault.folders(); folderLoadFailed = false }
        catch { folderLoadFailed = true }
    }

    @ViewBuilder private var loginFields: some View {
        group("登录凭据") {
            input("用户名", $login.username.editText, prompt: "用户名或邮箱", type: .username, capitals: .never)
            divider
            EditorSecretField(title: "密码", value: $login.password.editText, type: .newPassword, generate: generatePassword)
            if let password = login.password, !password.isEmpty {
                SecretStrengthMeter(strength: .estimate(password))
                    .padding(.horizontal, Spacing.lg).padding(.bottom, Spacing.sm)
            }
            divider
            EditorSecretField(title: "验证码", value: $login.totp.editText, prompt: "密钥或 otpauth:// 链接")
            if let codeError {
                Text(codeError).font(.footnote).foregroundStyle(.secondary)
                    .padding(.horizontal, Spacing.lg).padding(.bottom, Spacing.sm)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        group("网站") {
            ForEach($sites) { $site in
                let siteID = site.id
                HStack(spacing: Spacing.sm) {
                    VaultFieldButton(title: "删除网站", systemImage: "minus.circle", role: .destructive) {
                        sites.removeAll { $0.id == siteID }
                    }
                    TextField("网站", text: $site.value.uri, prompt: Text("https://"))
                        .textContentType(.URL).keyboardType(.URL)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .privacySensitive()
                }
                .padding(.leading, Spacing.xs).padding(.trailing, Spacing.lg).frame(minHeight: LayoutMetric.phoneRowHeight)
                divider
            }
            Button { sites.append(SiteDraft()) } label: {
                Label("添加网站", systemImage: "plus.circle")
                    .frame(maxWidth: .infinity, minHeight: LayoutMetric.phoneRowHeight, alignment: .leading)
            }
            .padding(.horizontal, Spacing.lg)
        }
    }

    private func generatePassword() {
        do { login.password = try PasswordGenerator.generate(.init(length: 20, useSpecial: true)) }
        catch { errorMessage = "无法生成密码，请重试。" }
    }

    private var cardFields: some View {
        group("银行卡") {
            input("持卡人", $card.cardholderName.editText, type: .name)
            divider
            input("品牌", $card.brand.editText)
            divider
            EditorSecretField(title: "卡号", value: $card.number.editText, type: .creditCardNumber, keyboard: .numberPad)
            divider
            editorRow("有效期") {
                HStack(spacing: Spacing.xs) {
                    expiryPicker("月", selection: $card.expMonth.editText, choices: (1...12).map { String($0) })
                    Text("/").foregroundStyle(.secondary)
                    expiryPicker("年", selection: $card.expYear.editText, choices: expiryYears)
                }
            }
            divider
            EditorSecretField(title: "安全码", value: $card.code.editText, prompt: "CVV", keyboard: .numberPad)
        }
    }

    private var expiryYears: [String] {
        let year = Calendar(identifier: .gregorian).component(.year, from: .now)
        return (year...(year + 30)).map { String($0) }
    }

    private func expiryPicker(_ title: String, selection: Binding<String>, choices: [String]) -> some View {
        Picker(title, selection: selection) {
            Text(title).tag("")
            if !selection.wrappedValue.isEmpty, !choices.contains(selection.wrappedValue) {
                Text(verbatim: selection.wrappedValue).tag(selection.wrappedValue)
            }
            ForEach(choices, id: \.self) { choice in Text(verbatim: choice).tag(choice) }
        }
        .labelsHidden().pickerStyle(.menu)
    }

    @ViewBuilder private var identityFields: some View {
        group("姓名与联系方式") {
            input("称谓", $identity.title.editText); divider
            input("姓氏", $identity.lastName.editText, type: .familyName); divider
            input("名字", $identity.firstName.editText, type: .givenName); divider
            input("中间名", $identity.middleName.editText, type: .middleName); divider
            input("用户名", $identity.username.editText, type: .username, capitals: .never); divider
            input("公司", $identity.company.editText, type: .organizationName); divider
            input("邮箱", $identity.email.editText, type: .emailAddress, capitals: .never, keyboard: .emailAddress); divider
            input("电话", $identity.phone.editText, type: .telephoneNumber, keyboard: .phonePad)
        }
        group("地址") {
            input("地址 1", $identity.address1.editText, type: .streetAddressLine1); divider
            input("地址 2", $identity.address2.editText, type: .streetAddressLine2); divider
            input("地址 3", $identity.address3.editText); divider
            input("城市", $identity.city.editText, type: .addressCity); divider
            input("省 / 州", $identity.state.editText, type: .addressState); divider
            input("邮政编码", $identity.postalCode.editText, type: .postalCode); divider
            input("国家或地区", $identity.country.editText, type: .countryName)
        }
        group("证件") {
            EditorSecretField(title: "社会安全号码", value: $identity.ssn.editText); divider
            EditorSecretField(title: "护照号码", value: $identity.passportNumber.editText); divider
            EditorSecretField(title: "证件号码", value: $identity.licenseNumber.editText)
        }
    }

    private var sshFields: some View {
        group("SSH 密钥") {
            EditorSecretField(title: "私钥", value: $ssh.privateKey.editText, multiline: true); divider
            input("公钥", $ssh.publicKey.editText, capitals: .never, multiline: true); divider
            input("指纹", $ssh.keyFingerprint.editText, capitals: .never)
            if isSSHKeyIncomplete {
                Text("SSH 密钥必须包含私钥、公钥和指纹。").font(.footnote).foregroundStyle(.secondary)
                    .padding(.horizontal, Spacing.lg).padding(.bottom, Spacing.sm)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private var notesField: some View {
        group("内容") { input("正文", $draft.notes.editText, prompt: "输入内容", multiline: true) }
    }

    private func group<Content: View>(_ title: String? = nil, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            if let title {
                Text(title).font(.subheadline.weight(.semibold)).foregroundStyle(.secondary)
                    .accessibilityAddTraits(.isHeader).padding(.horizontal, Spacing.lg)
            }
            OpenVaultCard(cornerRadius: sizeClass == .regular ? CornerRadius.iPadCard : CornerRadius.iPhoneCard, padding: 0) {
                VStack(spacing: 0) { content() }
            }
        }
    }

    private var divider: some View { Divider().padding(.leading, Spacing.lg) }

    private func editorRow<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        let layout = dynamicTypeSize.isAccessibilitySize ? AnyLayout(VStackLayout(alignment: .leading, spacing: Spacing.xs)) : AnyLayout(HStackLayout(alignment: .firstTextBaseline, spacing: Spacing.sm))
        return layout {
            Text(title).frame(minWidth: dynamicTypeSize.isAccessibilitySize ? 0 : 80, alignment: .leading)
                .accessibilityHidden(true)
            content().frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, Spacing.lg).padding(.vertical, Spacing.sm)
        .frame(maxWidth: .infinity, minHeight: LayoutMetric.phoneRowHeight, alignment: .leading)
    }

    private func input(_ title: String, _ value: Binding<String>, prompt: String? = nil,
                       type: UITextContentType? = nil, capitals: TextInputAutocapitalization = .words,
                       keyboard: UIKeyboardType = .default, multiline: Bool = false) -> some View {
        editorRow(title) {
            TextField(title, text: value, prompt: prompt.map { Text($0) } ?? Text(""), axis: multiline ? .vertical : .horizontal)
                .lineLimit(multiline ? 2...8 : 1...1).textContentType(type).keyboardType(keyboard)
                .textInputAutocapitalization(capitals).autocorrectionDisabled().privacySensitive()
                .accessibilityLabel(title)
        }
    }

    private func save() {
        guard canSave else { return }
        isSaving = true
        var item = draft
        item.name = item.name.trimmingCharacters(in: .whitespacesAndNewlines)
        switch kind {
        case .login:
            var updated = login
            updated.uris = sites.map(\.value).filter { !$0.uri.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
            if updated.password != original?.login?.password { updated.passwordRevisionDate = updated.password == nil ? nil : .now }
            item.login = updated
        case .card: item.card = card
        case .identity: item.identity = identity
        case .secureNote: item.secureNote = original?.secureNote ?? .init()
        case .sshKey: item.sshKey = ssh
        case .unknown: isSaving = false; return
        }
        let saved = item
        Task {
            defer { isSaving = false }
            do {
                let id: String
                if let original, let existingID = original.id {
                    let latest = try await vault.cipher(id: existingID)
                    guard latest == original else {
                        errorMessage = "此条目已更改，你的编辑尚未存储。取消编辑后重新打开条目，以查看最新内容。"
                        return
                    }
                    try await vault.updateCipher(id: existingID, saved)
                    id = existingID
                } else {
                    id = try await vault.createCipher(saved)
                }
                onSaved(id)
            } catch { errorMessage = "无法存储条目，请稍后再试。" }
        }
    }
}

struct VaultEditorSizing: PresentationSizing {
    let regular: Bool

    func proposedSize(for root: PresentationSizingRoot, context: PresentationSizingContext) -> ProposedViewSize {
        guard regular else { return FormPresentationSizing.form.proposedSize(for: root, context: context) }
        let page = PagePresentationSizing.page.proposedSize(for: root, context: context)
        return ProposedViewSize(width: min(620, page.width ?? 620), height: min(780, page.height ?? 780))
    }
}

private struct SiteDraft: Identifiable {
    let id = UUID()
    var value = PlaintextCipher.Uri(uri: "")
}

private extension Binding where Value == String? {
    var editText: Binding<String> {
        Binding<String>(get: { wrappedValue ?? "" }, set: { wrappedValue = $0.isEmpty ? nil : $0 })
    }
}

private extension CipherType {
    var editorLabel: String {
        switch self {
        case .login: "登录"
        case .card: "银行卡"
        case .identity: "身份"
        case .secureNote: "安全笔记"
        case .sshKey: "SSH 密钥"
        case .unknown: "条目"
        }
    }
    var editorTitle: String { self == .login ? "登录项" : editorLabel }
    var editorSymbol: String {
        switch self {
        case .login: "key"
        case .card: "creditcard"
        case .identity: "person.text.rectangle"
        case .secureNote: "note.text"
        case .sshKey: "terminal"
        case .unknown: "questionmark"
        }
    }
}

@available(iOS 27.0, *)
private struct EditorSecretField: View {
    let title: String
    @Binding var value: String
    var prompt: String? = nil
    var type: UITextContentType? = nil
    var keyboard: UIKeyboardType = .default
    var multiline = false
    var generate: (() -> Void)? = nil
    @State private var revealed = false
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        let layout = dynamicTypeSize.isAccessibilitySize ? AnyLayout(VStackLayout(alignment: .leading, spacing: Spacing.xs)) : AnyLayout(HStackLayout(spacing: Spacing.sm))
        layout {
            Text(title).frame(minWidth: dynamicTypeSize.isAccessibilitySize ? 0 : 80, alignment: .leading).accessibilityHidden(true)
            HStack(spacing: 0) {
                Group {
                    if revealed {
                        TextField(title, text: $value, prompt: Text(prompt ?? ""), axis: multiline ? .vertical : .horizontal)
                            .lineLimit(multiline ? 3...10 : 1...1)
                    } else { SecureField(title, text: $value, prompt: Text(prompt ?? "")) }
                }
                .font(Typography.secretValue).textContentType(type).keyboardType(keyboard)
                .textInputAutocapitalization(.never).autocorrectionDisabled().privacySensitive()
                .accessibilityLabel(title)
                if let generate { VaultFieldButton(title: "生成新密码", systemImage: "sparkles", action: generate) }
                VaultFieldButton(title: revealed ? "隐藏\(title)" : "显示\(title)", systemImage: revealed ? "eye.slash" : "eye") { revealed.toggle() }
            }
        }
        .padding(.leading, Spacing.lg).padding(.trailing, Spacing.xs)
        .padding(.vertical, Spacing.xs).frame(maxWidth: .infinity, minHeight: LayoutMetric.phoneRowHeight, alignment: .leading)
        .onChange(of: scenePhase) { _, phase in if phase != .active { revealed = false } }
    }
}
