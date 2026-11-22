import SwiftUI
import Accessibility
import DesignSystem
import Generators
import UIShared
import VaultModels
import VaultRepository

struct MacItemDetailView: View {
    let cipher: PlaintextCipher
    let vault: VaultService
    var folderName: String? = nil
    var onMoveToTrash: (() -> Void)? = nil
    var onArchive: (() -> Void)? = nil
    let onChanged: () -> Void

    @State private var showingEdit = false
    @State private var showingInfo = false
    @State private var updatingFavorite = false
    @State private var favoriteError = false
    @State private var copyReceipt: MacCopyReceipt?

    init(cipher: PlaintextCipher, vault: VaultService, folderName: String? = nil,
         onMoveToTrash: (() -> Void)? = nil, onArchive: (() -> Void)? = nil, onChanged: @escaping () -> Void) {
        self.cipher = cipher
        self.vault = vault
        self.folderName = folderName
        self.onMoveToTrash = onMoveToTrash
        self.onArchive = onArchive
        self.onChanged = onChanged
    }

    private var title: String { cipher.name.nilIfBlank ?? "未命名条目" }
    private var isActiveItem: Bool { cipher.deletedDate == nil && cipher.archivedDate == nil }
    private var canEdit: Bool { isActiveItem && cipher.id != nil && !updatingFavorite }
    private var configuration: TOTPConfiguration? {
        cipher.login?.totp.flatMap { try? TOTP.configuration(from: $0) }
    }
    private var subtitle: String {
        if let uri = cipher.login?.uris.first?.uri, let host = macWebsiteURL(uri)?.host { return host }
        return cipher.macTypeLabel
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 14) {
                    BrandBadge(title, diameter: 54)
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 8) {
                            Text(title).font(.system(size: 26, weight: .bold)).accessibilityAddTraits(.isHeader)
                            if cipher.favorite {
                                Image(systemName: "star.fill").foregroundStyle(.orange).accessibilityLabel("已置顶")
                            }
                        }
                        Text(subtitle).foregroundStyle(.secondary)
                    }
                }
                .padding(.bottom, 10)

                credentialFields
                if !cipher.fields.isEmpty {
                    Text("自定义字段").font(.headline)
                    OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 0) {
                        VStack(alignment: .leading, spacing: 0) {
                            ForEach(Array(cipher.fields.enumerated()), id: \.offset) { index, field in
                                let label = field.name?.nilIfBlank ?? "字段 \(index + 1)"
                                if index > 0 { divider }
                                if let value = field.value, !value.isEmpty {
                                    fieldRow(MacItemField("custom-\(index)", label, value, secret: field.type == FieldType.hidden.rawValue))
                                } else {
                                    LabeledContent(label, value: field.type == FieldType.linked.rawValue ? "关联字段" : "—")
                                        .padding(.horizontal, 14).frame(minHeight: 40)
                                }
                            }
                        }
                    }
                }
                if let note = cipher.notes?.nilIfBlank {
                    OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 14) {
                        VStack(alignment: .leading, spacing: 5) {
                            Text(cipher.type == CipherType.secureNote.rawValue ? "内容" : "备注")
                                .font(.caption).foregroundStyle(.secondary)
                            Text(note).textSelection(.enabled).privacySensitive()
                        }
                    }
                }
                VStack(alignment: .leading, spacing: 2) {
                    if let folderName { Text(folderName) }
                    if let date = cipher.creationDate { Text("创建于 \(date.formatted(date: .abbreviated, time: .shortened))") }
                    if let date = cipher.revisionDate { Text("上次修改于 \(date.formatted(date: .abbreviated, time: .shortened))") }
                }
                .font(.caption).foregroundStyle(.secondary)
            }
            .frame(maxWidth: 680, alignment: .leading)
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .scrollEdgeEffectStyle(.soft, for: .top)
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                if isActiveItem {
                    Button("编辑条目", systemImage: "pencil") { showingEdit = true }
                        .help("编辑条目").disabled(!canEdit)
                    if let onArchive {
                        Button("归档", systemImage: "archivebox", action: onArchive).help("归档").disabled(!canEdit)
                    }
                    if let onMoveToTrash {
                        Button("移到回收站", systemImage: "trash", action: onMoveToTrash).help("移到回收站").disabled(!canEdit)
                    }
                }
                Button("条目信息", systemImage: "info.circle") { showingInfo.toggle() }
                    .help("条目信息")
                    .popover(isPresented: $showingInfo) { information }
            }
        }
        .contextMenu {
            if isActiveItem {
                Button(cipher.favorite ? "取消置顶" : "置顶", systemImage: cipher.favorite ? "star.slash" : "star") {
                    toggleFavorite()
                }.disabled(!canEdit)
            }
            if let address = cipher.login?.uris.first?.uri, let url = macWebsiteURL(address) {
                ShareLink(item: url) { Label("共享网站…", systemImage: "square.and.arrow.up") }
            }
        }
        .focusedSceneValue(\.macItemCommands, showingEdit ? nil : commands)
        .sheet(isPresented: $showingEdit) {
            MacItemEditView(vault: vault, existing: cipher) { _ in onChanged() }
        }
        .alert("无法更改置顶状态", isPresented: $favoriteError) { Button("好", role: .cancel) {} }
        .task(id: copyReceipt?.token) {
            guard copyReceipt != nil else { return }
            do { try await Task.sleep(for: .milliseconds(1600)) } catch { return }
            copyReceipt = nil
        }
    }

    @ViewBuilder private var credentialFields: some View {
        switch CipherType(rawValue: cipher.type) {
        case .login:
            if let login = cipher.login {
                let loginFields = [MacItemField("username", "用户名", login.username),
                                   MacItemField("password", "密码", login.password, secret: true)]
                if loginFields.contains(where: { $0.value != nil }) || configuration != nil || !login.fido2Credentials.isEmpty {
                    OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 0) {
                        VStack(alignment: .leading, spacing: 0) {
                            rows(loginFields)
                            if let configuration {
                                if loginFields.contains(where: { $0.value != nil }) { divider }
                                TimelineView(.periodic(from: .now, by: 1)) { context in
                                    MacCodeCopyRow(configuration: configuration, date: context.date,
                                                   copied: copyReceipt?.field == "totp") { copyCode(configuration) }
                                }
                            }
                            ForEach(Array(login.fido2Credentials.enumerated()), id: \.offset) { index, credential in
                                if index > 0 || configuration != nil || loginFields.contains(where: { $0.value != nil }) { divider }
                                VStack(alignment: .leading, spacing: 3) {
                                    Text("通行密钥").font(.caption).foregroundStyle(.secondary)
                                    Label(credential.rpName?.nilIfBlank ?? credential.rpId?.nilIfBlank ?? "已保存", systemImage: "person.badge.key")
                                }.padding(.horizontal, 14).padding(.vertical, 8)
                            }
                        }
                    }
                }
                if !login.uris.isEmpty {
                    OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 0) {
                        VStack(alignment: .leading, spacing: 0) {
                            ForEach(Array(login.uris.enumerated()), id: \.offset) { index, uri in
                                if index > 0 { divider }
                                if let url = macWebsiteURL(uri.uri) {
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text("网站").font(.caption).foregroundStyle(.secondary)
                                        Link(destination: url) {
                                            Label(url.host ?? uri.uri, systemImage: "arrow.up.right").lineLimit(1)
                                        }
                                        .contextMenu {
                                            Button("拷贝网址") { copy(uri.uri, field: "uri-\(index)") }
                                            ShareLink(item: url)
                                        }
                                        if copyReceipt?.field == "uri-\(index)" { InlineCopyIndicator() }
                                    }.padding(.horizontal, 14).padding(.vertical, 8)
                                } else {
                                    fieldRow(MacItemField("uri-\(index)", "网站", uri.uri))
                                }
                            }
                        }
                    }
                }
            }
        case .card:
            if let card = cipher.card {
                fieldCard(for: [MacItemField("holder", "持卡人", card.cardholderName), MacItemField("brand", "品牌", card.brand),
                                MacItemField("number", "卡号", card.number, secret: true),
                                MacItemField("expiry", "有效期", [card.expMonth, card.expYear].compactMap { $0?.nilIfBlank }.joined(separator: "/")),
                                MacItemField("cvv", "安全码", card.code, secret: true)])
            }
        case .identity:
            if let identity = cipher.identity {
                fieldCard(for: [MacItemField("title", "称谓", identity.title), MacItemField("first", "名字", identity.firstName),
                                MacItemField("middle", "中间名", identity.middleName), MacItemField("last", "姓氏", identity.lastName),
                                MacItemField("company", "公司", identity.company), MacItemField("account", "用户名", identity.username),
                                MacItemField("email", "邮箱", identity.email), MacItemField("phone", "电话", identity.phone)])
                fieldCard(for: [MacItemField("address1", "地址 1", identity.address1), MacItemField("address2", "地址 2", identity.address2),
                                MacItemField("address3", "地址 3", identity.address3), MacItemField("city", "城市", identity.city),
                                MacItemField("state", "省/州", identity.state), MacItemField("zip", "邮编", identity.postalCode),
                                MacItemField("country", "国家/地区", identity.country)])
                fieldCard(for: [MacItemField("ssn", "社会安全号", identity.ssn, secret: true),
                                MacItemField("passport", "护照号码", identity.passportNumber, secret: true),
                                MacItemField("license", "驾照号码", identity.licenseNumber, secret: true)])
            }
        case .sshKey:
            if let ssh = cipher.sshKey {
                fieldCard(for: [MacItemField("privateKey", "私钥", ssh.privateKey, secret: true),
                                MacItemField("publicKey", "公钥", ssh.publicKey), MacItemField("fingerprint", "指纹", ssh.keyFingerprint)])
            }
        case .secureNote: EmptyView()
        case .unknown: ContentUnavailableView("无法显示此类型", systemImage: "questionmark.square.dashed")
        }
    }

    @ViewBuilder private func fieldCard(for fields: [MacItemField]) -> some View {
        if fields.contains(where: { $0.value != nil }) {
            OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 0) {
                VStack(alignment: .leading, spacing: 0) { rows(fields) }
            }
        }
    }

    private func rows(_ fields: [MacItemField]) -> some View {
        let visible = fields.filter { $0.value != nil }
        return ForEach(visible) { field in
            if visible.first?.id != field.id { divider }
            fieldRow(field)
        }
    }

    private func fieldRow(_ field: MacItemField) -> some View {
        MacFieldCopyRow(field: field, copied: copyReceipt?.field == field.id) {
            if let value = field.value { copy(value, field: field.id) }
        }
    }

    private var divider: some View { Divider().padding(.leading, 14) }

    private var information: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.headline)
            LabeledContent("类型", value: cipher.macTypeLabel)
            LabeledContent("文件夹", value: folderName ?? (cipher.folderID == nil ? "无文件夹" : "—"))
            if let date = cipher.creationDate { LabeledContent("创建时间", value: date.formatted()) }
            if let date = cipher.revisionDate { LabeledContent("修改时间", value: date.formatted()) }
            LabeledContent("置顶", value: cipher.favorite ? "是" : "否")
            if let id = cipher.id { LabeledContent("条目 ID") { Text(id).textSelection(.enabled) } }
            if let date = cipher.login?.passwordRevisionDate { LabeledContent("密码修改", value: date.formatted()) }
        }.padding(16).frame(minWidth: 260, maxWidth: 360)
    }

    private var commands: MacItemCommandActions {
        MacItemCommandActions(edit: canEdit ? { showingEdit = true } : nil,
                              info: { showingInfo.toggle() },
                              username: copyAction(cipher.login?.username, field: "username"),
                              password: copyAction(cipher.login?.password, field: "password"),
                              code: configuration.map { config in { copyCode(config) } })
    }

    private func copyAction(_ value: String?, field: String) -> (() -> Void)? {
        guard let value, !value.isEmpty else { return nil }
        return { copy(value, field: field) }
    }

    private func copyCode(_ configuration: TOTPConfiguration) { copy(TOTP.code(for: configuration, at: .now), field: "totp") }

    private func copy(_ value: String, field: String) {
        MacClipboard.copy(value)
        if let id = cipher.id, isActiveItem { Task { await vault.recordUse(id: id) } }
        copyReceipt = MacCopyReceipt(field: field)
        AccessibilityNotification.Announcement("已拷贝").post()
    }

    private func toggleFavorite() {
        guard canEdit, let id = cipher.id else { return }
        updatingFavorite = true
        Task {
            defer { updatingFavorite = false }
            do {
                var updated = try await vault.cipher(id: id)
                updated.favorite.toggle()
                try await vault.updateCipher(id: id, updated)
                onChanged()
            } catch { favoriteError = true }
        }
    }
}

private struct MacCopyReceipt { let field: String; let token = UUID() }

private struct MacItemField: Identifiable {
    let id: String
    let label: String
    let value: String?
    let secret: Bool

    init(_ id: String, _ label: String, _ value: String?, secret: Bool = false) {
        self.id = id; self.label = label; self.value = value?.isEmpty == false ? value : nil; self.secret = secret
    }
}

private struct MacFieldCopyRow: View {
    let field: MacItemField
    let copied: Bool
    let action: () -> Void
    @State private var hovered = false
    @FocusState private var focused: Bool
    @Environment(\.appearsActive) private var active

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 3) {
                Text(field.label).font(.caption).foregroundStyle(.secondary)
                HStack(spacing: 8) {
                    if field.secret {
                        if active && (hovered || focused) {
                            ColoredSecretText(field.value ?? "").font(.body.monospaced()).lineLimit(8).privacySensitive()
                        } else {
                            Text("••••••••••••").font(.body.monospaced())
                        }
                    } else {
                        Text(field.value ?? "").lineLimit(4).truncationMode(.middle).privacySensitive()
                    }
                    if copied { InlineCopyIndicator() }
                }
            }
            .padding(.horizontal, 14).padding(.vertical, 7)
            .frame(maxWidth: .infinity, minHeight: 46, alignment: .leading).contentShape(Rectangle())
        }
        .buttonStyle(.plain).focused($focused).onHover { hovered = $0 }
        .accessibilityLabel("拷贝\(field.label)")
        .accessibilityValue(copied ? "已拷贝" : field.secret ? "" : field.value ?? "")
    }
}

private struct MacCodeCopyRow: View {
    let configuration: TOTPConfiguration
    let date: Date
    let copied: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 3) {
                Text("验证码").font(.caption).foregroundStyle(.secondary)
                HStack(spacing: 8) {
                    Text(OTPRingMath.formatCode(TOTP.code(for: configuration, at: date)))
                        .font(.title2.monospaced().weight(.semibold)).privacySensitive()
                    if copied { InlineCopyIndicator() }
                }
            }
            .padding(.horizontal, 14).padding(.vertical, 8)
            .frame(maxWidth: .infinity, minHeight: 52, alignment: .leading)
            .overlay(alignment: .bottom) {
                OTPCountdownBar(secondsRemaining: TOTP.secondsRemaining(for: configuration, at: date), period: configuration.period)
                    .padding(.horizontal, 14)
            }.contentShape(Rectangle())
        }.buttonStyle(.plain).accessibilityLabel("拷贝验证码").accessibilityValue(copied ? "已拷贝" : "")
    }
}

func macWebsiteURL(_ value: String) -> URL? {
    guard let input = value.nilIfBlank else { return nil }
    let address = URLComponents(string: input)?.scheme == nil ? "https://\(input)" : input
    guard let url = URL(string: address), let scheme = url.scheme?.lowercased(),
          ["https", "http"].contains(scheme), url.host?.isEmpty == false else { return nil }
    return url
}

struct MacItemCommandActions {
    let edit: (() -> Void)?
    let info: (() -> Void)?
    let username: (() -> Void)?
    let password: (() -> Void)?
    let code: (() -> Void)?
}

extension FocusedValues { @Entry var macItemCommands: MacItemCommandActions? }

struct MacItemCommands: Commands {
    @FocusedValue(\.macItemCommands) private var actions

    var body: some Commands {
        CommandGroup(after: .pasteboard) {
            Divider()
            Button("拷贝用户名") { actions?.username?() }.keyboardShortcut("u", modifiers: [.shift, .command]).disabled(actions?.username == nil)
            Button("拷贝密码") { actions?.password?() }.keyboardShortcut("c", modifiers: [.shift, .command]).disabled(actions?.password == nil)
            Button("拷贝验证码") { actions?.code?() }.keyboardShortcut("c", modifiers: [.option, .command]).disabled(actions?.code == nil)
            Divider()
            Button("编辑条目…") { actions?.edit?() }.keyboardShortcut("e", modifiers: [.command]).disabled(actions?.edit == nil)
            Button("条目信息") { actions?.info?() }.keyboardShortcut("i", modifiers: [.command]).disabled(actions?.info == nil)
        }
    }
}
