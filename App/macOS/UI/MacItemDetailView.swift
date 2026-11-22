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
    let onEdit: () -> Void
    let onChanged: () -> Void

    @State private var showingInfo = false
    @State private var updatingFavorite = false
    @State private var favoriteError = false
    @State private var copyReceipt: MacCopyReceipt?

    init(cipher: PlaintextCipher, vault: VaultService, folderName: String? = nil,
         onMoveToTrash: (() -> Void)? = nil, onArchive: (() -> Void)? = nil,
         onEdit: @escaping () -> Void, onChanged: @escaping () -> Void) {
        self.cipher = cipher
        self.vault = vault
        self.folderName = folderName
        self.onMoveToTrash = onMoveToTrash
        self.onArchive = onArchive
        self.onEdit = onEdit
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
    private var metadata: String {
        let folder = folderName ?? (cipher.folderID == nil ? "无文件夹" : nil)
        let revision = cipher.revisionDate.map { "上次修改于 \($0.formatted(date: .abbreviated, time: .shortened))" }
        return [folder, revision].compactMap { $0 }.joined(separator: " · ")
    }

    var body: some View {
        MacDetailColumn {
            HStack(spacing: 16) {
                BrandBadge(cipher, diameter: 64)
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 8) {
                        Text(title).font(.system(size: 26, weight: .bold)).accessibilityAddTraits(.isHeader)
                        if cipher.id != nil && isActiveItem {
                            Button(cipher.favorite ? "取消置顶" : "置顶", systemImage: cipher.favorite ? "star.fill" : "star", action: toggleFavorite)
                                .labelStyle(.iconOnly).buttonStyle(.borderless)
                                .foregroundStyle(cipher.favorite ? Color.orange : .secondary)
                                .help(cipher.favorite ? "取消置顶" : "置顶").disabled(!canEdit)
                        }
                    }
                    Text(subtitle).foregroundStyle(.secondary)
                }
            }
            .padding(.bottom, 12)

            credentialFields
            if !cipher.fields.isEmpty {
                Text("自定义字段").font(.headline)
                MacDetailCard {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(cipher.fields.enumerated()), id: \.offset) { index, field in
                            let label = field.name?.nilIfBlank ?? "字段 \(index + 1)"
                            if index > 0 { divider }
                            if let value = field.value, !value.isEmpty {
                                fieldRow(MacItemField("custom-\(index)", label, value, secret: field.type == FieldType.hidden.rawValue))
                            } else {
                                MacDetailRow(label) { Text(field.type == FieldType.linked.rawValue ? "关联字段" : "—") }
                            }
                        }
                    }
                }
            }
            if let note = cipher.notes?.nilIfBlank {
                MacDetailCard {
                    MacDetailRow(cipher.type == CipherType.secureNote.rawValue ? "内容" : "备注", alignment: .top) {
                        Text(note).textSelection(.enabled).privacySensitive()
                    }
                }
            }
            if !metadata.isEmpty {
                Text(metadata).font(.caption).foregroundStyle(.secondary).padding(.leading, 16)
            }
        }
        .scrollEdgeEffectStyle(.soft, for: .top)
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                if isActiveItem {
                    Button("编辑条目", systemImage: "pencil", action: onEdit)
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
        .focusedSceneValue(\.macItemCommands, commands)
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
                    MacDetailCard {
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
                                MacDetailRow("通行密钥") {
                                    Label(credential.rpName?.nilIfBlank ?? credential.rpId?.nilIfBlank ?? "已保存", systemImage: "person.badge.key")
                                }
                            }
                        }
                    }
                }
                if !login.uris.isEmpty {
                    MacDetailCard {
                        VStack(alignment: .leading, spacing: 0) {
                            ForEach(Array(login.uris.enumerated()), id: \.offset) { index, uri in
                                if index > 0 { divider }
                                if let url = macWebsiteURL(uri.uri) {
                                    MacDetailRow("网站") {
                                        HStack(spacing: 8) {
                                            Link(destination: url) {
                                                HStack(spacing: 4) {
                                                    Text(url.host ?? uri.uri).lineLimit(1)
                                                    Image(systemName: "arrow.up.right").font(.caption).accessibilityHidden(true)
                                                }
                                            }
                                            .contextMenu {
                                                Button("拷贝网址") { copy(uri.uri, field: "uri-\(index)") }
                                                ShareLink(item: url)
                                            }
                                            if copyReceipt?.field == "uri-\(index)" { InlineCopyIndicator() }
                                        }
                                    }
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
            MacDetailCard {
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

    private var divider: some View { Divider().padding(.leading, 16) }

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
        MacItemCommandActions(edit: canEdit ? onEdit : nil,
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

struct MacDetailColumn<Content: View>: View {
    @ViewBuilder let content: () -> Content

    var body: some View {
        GeometryReader { geometry in
            ScrollView {
                VStack(alignment: .leading, spacing: 12, content: content)
                    .frame(maxWidth: 760, alignment: .leading)
                    .padding(.horizontal, geometry.size.width >= 520 ? 40 : 16)
                    .padding(.vertical, 24)
                    .frame(maxWidth: .infinity, alignment: .top)
            }
        }
    }
}

struct MacDetailCard<Content: View>: View {
    @Environment(\.colorSchemeContrast) private var contrast
    @ViewBuilder let content: () -> Content

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: CornerRadius.macCard, style: .continuous)
        content()
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Palette.contentBackground, in: shape)
            .clipShape(shape)
            .overlay { shape.strokeBorder(Palette.separator, lineWidth: contrast == .increased ? 1 : 0.5).allowsHitTesting(false) }
    }
}

struct MacDetailRow<Content: View>: View {
    let label: String
    let alignment: VerticalAlignment
    let minimumHeight: CGFloat
    @ViewBuilder let content: () -> Content

    init(_ label: String, alignment: VerticalAlignment = .center, minimumHeight: CGFloat = 40,
         @ViewBuilder content: @escaping () -> Content) {
        self.label = label
        self.alignment = alignment
        self.minimumHeight = minimumHeight
        self.content = content
    }

    var body: some View {
        HStack(alignment: alignment, spacing: 12) {
            Text(label).foregroundStyle(.secondary).frame(width: 88, alignment: .leading)
            content().frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.leading, 16).padding(.trailing, 12).padding(.vertical, 6)
        .frame(maxWidth: .infinity, minHeight: minimumHeight, alignment: .leading)
        .contentShape(Rectangle())
    }
}

private struct MacDetailCopyRow<Value: View>: View {
    let label: String
    let copied: Bool
    let action: () -> Void
    @ViewBuilder let value: (Bool) -> Value
    @State private var hovered = false
    @FocusState private var focused: Bool
    @Environment(\.appearsActive) private var active
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var highlighted: Bool { active && (hovered || focused) }

    var body: some View {
        Button(action: action) {
            MacDetailRow(label, minimumHeight: 44) {
                HStack(spacing: 8) {
                    value(highlighted)
                    Spacer(minLength: 0)
                    if copied { InlineCopyIndicator() }
                    else if highlighted { Image(systemName: "document.on.document").foregroundStyle(.secondary).accessibilityHidden(true) }
                }
            }
            .background(highlighted ? Palette.controlFill.opacity(0.5) : .clear, in: .rect(cornerRadius: 8))
            .animation(reduceMotion ? nil : .easeOut(duration: 0.12), value: highlighted)
        }
        .buttonStyle(.plain).focused($focused).onHover { hovered = $0 }
        .accessibilityLabel("拷贝\(label)")
    }
}

private struct MacFieldCopyRow: View {
    let field: MacItemField
    let copied: Bool
    let action: () -> Void

    var body: some View {
        MacDetailCopyRow(label: field.label, copied: copied, action: action) { revealed in
            if field.secret {
                if revealed {
                    ColoredSecretText(field.value ?? "").font(.body.monospaced()).lineLimit(8)
                } else {
                    Text("••••••••••••").font(.body.monospaced())
                }
            } else {
                Text(field.value ?? "").lineLimit(4).truncationMode(.middle).privacySensitive()
            }
        }
        .accessibilityValue(copied ? "已拷贝" : field.secret ? "" : field.value ?? "")
    }
}

struct MacCodeCopyRow: View {
    let configuration: TOTPConfiguration
    let date: Date
    let copied: Bool
    let action: () -> Void

    var body: some View {
        let seconds = TOTP.secondsRemaining(for: configuration, at: date)
        MacDetailCopyRow(label: "验证码", copied: copied, action: action) { _ in
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text(OTPRingMath.formatCode(TOTP.code(for: configuration, at: date)))
                    .font(.title2.monospaced().weight(.semibold)).privacySensitive()
                if seconds <= 5 { OTPRowStatus(seconds: seconds, copied: false, font: .caption) }
            }
        }
        .overlay(alignment: .bottom) {
            OTPCountdownBar(secondsRemaining: seconds, period: configuration.period).allowsHitTesting(false)
        }
        .accessibilityValue(copied ? "已拷贝" : "\(seconds) 秒后更新")
        .accessibilityHint(Text("剩余 \(seconds) 秒"), isEnabled: copied && seconds <= 5)
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
    @FocusedValue(\.macWorkspaceActions) private var workspace
    @FocusedValue(\.macSendActions) private var send

    var body: some Commands {
        CommandGroup(after: .pasteboard) {
            Divider()
            Button("拷贝用户名") { actions?.username?() }.keyboardShortcut("u", modifiers: [.shift, .command]).disabled(workspace == nil || actions?.username == nil)
            Button("拷贝密码") { actions?.password?() }.keyboardShortcut("c", modifiers: [.shift, .command]).disabled(workspace == nil || actions?.password == nil)
            Button("拷贝验证码") { actions?.code?() }.keyboardShortcut("c", modifiers: [.option, .command]).disabled(workspace == nil || actions?.code == nil)
            Divider()
            Button(send == nil ? "编辑条目…" : "编辑 Send…") {
                if let send { send.edit() } else { actions?.edit?() }
            }.keyboardShortcut("e").disabled(workspace == nil || (actions?.edit == nil && send == nil))
            Button("条目信息") { actions?.info?() }.keyboardShortcut("i", modifiers: [.command]).disabled(workspace == nil || actions?.info == nil)
        }
    }
}
