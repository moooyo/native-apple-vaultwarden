import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels
import Generators

@available(iOS 27.0, *)
public struct ItemDetailView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.vaultFeedback) private var feedback
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor
    @State private var model: ItemDetailModel
    @State private var editing = false
    @State private var working = false
    @State private var errorMessage: String?
    @State private var confirmDeletion = false
    @State private var folders: [PlaintextFolder] = []
    @State private var foldersAvailable = false
    @State private var websiteCopyID: UUID?
    @State private var revealSession = UUID()

    private let sourceCipher: PlaintextCipher
    private let vault: VaultService
    private let isSplitDetail: Bool
    private let onSelectClone: ((String) -> Void)?
    private let onChanged: () -> Void

    public init(model: ItemDetailModel, vault: VaultService, isSplitDetail: Bool = false,
                onSelectClone: ((String) -> Void)? = nil, onChanged: @escaping () -> Void) {
        _model = State(initialValue: model)
        self.sourceCipher = model.cipher
        self.vault = vault
        self.isSplitDetail = isSplitDetail
        self.onSelectClone = onSelectClone
        self.onChanged = onChanged
    }

    private var cipher: PlaintextCipher { model.cipher }
    private var radius: CGFloat { isSplitDetail ? CornerRadius.iPadCard : CornerRadius.iPhoneCard }

    private var editable: Bool {
        guard cipher.id != nil, cipher.archivedDate == nil, cipher.deletedDate == nil else { return false }
        if case .unknown = CipherType(rawValue: cipher.type) { return false }
        return true
    }

    public var body: some View {
        Group {
            if editing {
                ItemEditView(vault: vault, existing: cipher, onCancel: { editing = false },
                             onTrash: { changeStatus(.trash) }) { id in
                    editing = false
                    perform { model.replaceCipher(try await vault.cipher(id: id)) }
                    onChanged()
                }
            } else {
                ScrollView {
                    VStack(spacing: Spacing.lg) {
                        header
                        fields
                        links
                        if !cipher.fields.isEmpty {
                            fieldCard(cipher.fields.enumerated().map { index, field in
                                DetailField("custom.\(index)", field.name?.nonblank ?? "自定义字段 \(index + 1)",
                                            field.value, secret: FieldType(rawValue: field.type) == .hidden)
                            })
                        }
                        if let notes = cipher.notes?.nonblank {
                            OpenVaultCard(cornerRadius: radius) {
                                VStack(alignment: .leading, spacing: Spacing.xs) {
                                    Text("备注").font(.footnote).foregroundStyle(.secondary)
                                    Text(verbatim: notes).textSelection(.enabled).privacySensitive()
                                }
                            }
                        }
                    }
                    .frame(maxWidth: LayoutMetric.padDetailWidth)
                    .padding(Spacing.lg)
                    .frame(maxWidth: .infinity)
                }
                .background(Palette.groupedBackground)
                .navigationTitle("")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar { detailToolbar }
                .id(revealSession)
            }
        }
        .disabled(working)
        .task(id: sourceCipher.id) {
            if !isSplitDetail, let id = sourceCipher.id, sourceCipher.deletedDate == nil, sourceCipher.archivedDate == nil {
                await vault.recordUse(id: id)
            }
            if isSplitDetail { await loadFolders() }
        }
        .onChange(of: sourceCipher) { old, new in
            if old.id != new.id || new.deletedDate != nil || new.archivedDate != nil { editing = false }
            model.replaceCipher(new)
            websiteCopyID = nil
            revealSession = UUID()
        }
        .onChange(of: scenePhase) { _, phase in
            if phase != .active { revealSession = UUID() }
        }
        .alert("操作未完成", isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(errorMessage ?? "") }
    }

    private var header: some View {
        let layout = isSplitDetail ? AnyLayout(HStackLayout(spacing: Spacing.lg)) : AnyLayout(VStackLayout(spacing: Spacing.sm))
        return layout {
            BrandBadge(cipher, diameter: 64)
            VStack(alignment: isSplitDetail ? .leading : .center, spacing: Spacing.xs) {
                Text(cipher.openVaultName).font(isSplitDetail ? .title.bold() : .title2.bold())
                    .accessibilityAddTraits(.isHeader)
                Text(metadata).font(.footnote).foregroundStyle(.secondary)
            }
        }
        .multilineTextAlignment(isSplitDetail ? .leading : .center)
        .frame(maxWidth: .infinity, alignment: isSplitDetail ? .leading : .center)
        .padding(.bottom, Spacing.sm)
    }

    private var metadata: String {
        var parts = [cipher.openVaultKindLabel]
        if isSplitDetail {
            if let id = cipher.folderID {
                if let folder = folders.first(where: { $0.id == id }) { parts.append(folder.name) }
            } else { parts.append("无文件夹") }
        }
        if let deleted = cipher.deletedDate { parts.append("\(deleted.formatted(.dateTime.month().day()))移到回收站") }
        else if let archived = cipher.archivedDate { parts.append("\(archived.formatted(.dateTime.month().day()))归档") }
        else if let revision = cipher.revisionDate { parts.append("\(revision.formatted(.dateTime.month().day()))修改") }
        return parts.joined(separator: " · ")
    }

    @ToolbarContentBuilder private var detailToolbar: some ToolbarContent {
        if cipher.deletedDate != nil {
            ToolbarItemGroup(placement: .topBarTrailing) {
                Button("恢复") { changeStatus(.restore) }
                Button("永久删除", role: .destructive) { confirmDeletion = true }
                    .confirmationDialog("永久删除“\(cipher.openVaultName)”？", isPresented: $confirmDeletion, titleVisibility: .visible) {
                        Button("永久删除", role: .destructive) { changeStatus(.delete) }
                        Button("取消", role: .cancel) {}
                    } message: { Text(TrashRemovalBatch.confirmationMessage) }
            }
        } else if cipher.archivedDate != nil {
            ToolbarItemGroup(placement: .topBarTrailing) {
                Button("取消归档") { changeStatus(.unarchive) }
                Button("移到回收站", systemImage: "trash", role: .destructive) { changeStatus(.trash) }
            }
        } else {
            if editable {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("编辑") { editing = true }.accessibilityIdentifier("item.edit")
                }
                ToolbarSpacer(.fixed, placement: .topBarTrailing)
            }
            ToolbarItemGroup(placement: .topBarTrailing) {
                if editable {
                    Button(cipher.favorite ? "取消置顶" : "置顶", systemImage: cipher.favorite ? "star.fill" : "star") {
                        update { $0.favorite.toggle() }
                    }
                    .accessibilityIdentifier("item.favorite")
                }
                Menu {
                    if let uri = cipher.login?.uris.first?.uri, !uri.isEmpty {
                        Button("拷贝网址", systemImage: "doc.on.doc") {
                            copyValue(uri)
                            websiteCopyID = UUID()
                        }
                    }
                    if isSplitDetail, editable {
                        if cipher.organizationID == nil {
                            Button("克隆", systemImage: "plus.square.on.square", action: clone)
                        }
                        Menu("移到文件夹", systemImage: "folder") {
                            if foldersAvailable {
                                folderOption(nil, name: "无文件夹")
                                ForEach(folders, id: \.id) { folder in folderOption(folder.id, name: folder.name) }
                            } else {
                                Button("重新载入文件夹") { Task { await loadFolders() } }
                            }
                        }
                    }
                    if cipher.id != nil {
                        Button("归档", systemImage: "archivebox") { changeStatus(.archive) }
                            .accessibilityIdentifier("item.archive")
                        Button("移到回收站", systemImage: "trash", role: .destructive) { changeStatus(.trash) }
                            .accessibilityIdentifier("item.trash")
                    }
                } label: { Label("更多操作", systemImage: "ellipsis") }
                .accessibilityIdentifier("item.more")
            }
        }
    }

    private func folderOption(_ id: String?, name: String) -> some View {
        Button {
            if cipher.folderID != id { update { $0.folderID = id } }
        } label: {
            if cipher.folderID == id { Label(name, systemImage: "checkmark") } else { Text(name) }
        }
    }

    @ViewBuilder private var fields: some View {
        switch CipherType(rawValue: cipher.type) {
        case .login:
            if let login = cipher.login {
                let rows = [DetailField("username", "用户名", login.username),
                            DetailField("password", "密码", login.password, secret: true)].filter { $0.value != nil }
                if !rows.isEmpty || model.hasTOTP {
                    OpenVaultCard(cornerRadius: radius, padding: 0) {
                        VStack(spacing: 0) {
                            ForEach(rows) { row in
                                DetailCopyRow(field: row, copy: copyValue)
                                if row.id != rows.last?.id || model.hasTOTP { divider }
                            }
                            if let configuration = model.totpConfiguration { codeRow(configuration) }
                        }
                        .clipShape(.rect(cornerRadius: radius))
                    }
                }
            }
        case .card:
            if let card = cipher.card {
                let expiration = [card.expMonth, card.expYear].compactMap { $0?.nonblank }.joined(separator: " / ")
                fieldCard([.init("holder", "持卡人", card.cardholderName), .init("brand", "品牌", card.brand),
                           .init("number", "卡号", card.number, secret: true), .init("expiry", "有效期", expiration),
                           .init("securityCode", "安全码", card.code, secret: true)])
            }
        case .identity:
            if let identity = cipher.identity {
                fieldCard([.init("title", "称谓", identity.title), .init("firstName", "名字", identity.firstName),
                           .init("middleName", "中间名", identity.middleName), .init("lastName", "姓氏", identity.lastName),
                           .init("username", "用户名", identity.username), .init("company", "公司", identity.company),
                           .init("email", "邮箱", identity.email), .init("phone", "电话", identity.phone)])
                fieldCard([.init("address1", "地址 1", identity.address1), .init("address2", "地址 2", identity.address2),
                           .init("address3", "地址 3", identity.address3), .init("city", "城市", identity.city),
                           .init("state", "省 / 州", identity.state), .init("postal", "邮政编码", identity.postalCode),
                           .init("country", "国家或地区", identity.country)])
                fieldCard([.init("ssn", "社会安全号码", identity.ssn, secret: true),
                           .init("passport", "护照号码", identity.passportNumber, secret: true),
                           .init("license", "证件号码", identity.licenseNumber, secret: true)])
            }
        case .sshKey:
            if let ssh = cipher.sshKey {
                fieldCard([.init("privateKey", "私钥", ssh.privateKey, secret: true),
                           .init("publicKey", "公钥", ssh.publicKey), .init("fingerprint", "指纹", ssh.keyFingerprint)])
            }
        case .secureNote:
            EmptyView()
        case .unknown:
            OpenVaultCard(cornerRadius: radius) { Label("不支持此条目类型", systemImage: "questionmark.folder") }
        }
    }

    @ViewBuilder private func fieldCard(_ fields: [DetailField]) -> some View {
        let visible = fields.filter { $0.value != nil }
        if !visible.isEmpty {
            OpenVaultCard(cornerRadius: radius, padding: 0) {
                VStack(spacing: 0) {
                    ForEach(visible) { field in
                        DetailCopyRow(field: field, copy: copyValue)
                        if field.id != visible.last?.id { divider }
                    }
                }
            }
        }
    }

    private func codeRow(_ configuration: TOTPConfiguration) -> some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let raw = TOTP.code(for: configuration, at: context.date)
            let seconds = TOTP.secondsRemaining(for: configuration, at: context.date)
            InlineCopyButton(action: { copyValue(TOTP.code(for: configuration, at: .now)) }) { copied in
                let value = VStack(alignment: .leading, spacing: Spacing.xxs) {
                    Text("验证码").font(.footnote).foregroundStyle(.secondary)
                    VaultCodeText(value: raw, font: .system(.title, design: .monospaced).weight(.semibold))
                }
                let status = OTPRowStatus(seconds: seconds, copied: copied, showsSecondsNormally: differentiateWithoutColor)
                VStack(spacing: 0) {
                    ViewThatFits(in: .horizontal) {
                        HStack { value; Spacer(minLength: Spacing.xs); status }
                        VStack(alignment: .leading, spacing: Spacing.xs) { value; status }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, Spacing.lg).padding(.vertical, Spacing.sm).frame(minHeight: 73)
                    OTPCountdownBar(secondsRemaining: seconds, period: configuration.period)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("拷贝验证码")
            .accessibilityHint("剩余 \(seconds) 秒")
            .accessibilityIdentifier("item.copyCode")
        }
    }

    @ViewBuilder private var links: some View {
        if let login = cipher.login, !login.uris.isEmpty || !login.fido2Credentials.isEmpty {
            OpenVaultCard(cornerRadius: radius, padding: 0) {
                VStack(spacing: 0) {
                    ForEach(Array(login.uris.enumerated()), id: \.offset) { index, entry in
                        if let url = siteURL(entry.uri) {
                            Link(destination: url) {
                                HStack(spacing: Spacing.md) {
                                    linkIcon("globe")
                                    VStack(alignment: .leading) {
                                        Text("网站").font(.footnote).foregroundStyle(Palette.secondaryText)
                                        Text(verbatim: url.formatted(.url.scheme(.never).path(.always)))
                                            .lineLimit(2).truncationMode(.middle).privacySensitive()
                                    }
                                    Spacer()
                                    if index == 0, websiteCopyID != nil { InlineCopyIndicator() }
                                    else { Image(systemName: "arrow.up.right.square").foregroundStyle(Palette.secondaryText) }
                                }
                                .padding(.horizontal, Spacing.lg).frame(minHeight: 60).contentShape(Rectangle())
                            }
                        } else {
                            DetailCopyRow(field: .init("url.\(index)", "网站", entry.uri), copy: copyValue,
                                          copiedExternally: index == 0 && websiteCopyID != nil)
                        }
                        if index < login.uris.count - 1 || !login.fido2Credentials.isEmpty { divider }
                    }
                    if !login.fido2Credentials.isEmpty {
                        HStack(spacing: Spacing.md) { linkIcon("person.badge.key"); Text("通行密钥") }
                            .frame(maxWidth: .infinity, minHeight: 52, alignment: .leading)
                            .padding(.horizontal, Spacing.lg)
                    }
                }
            }
            .task(id: websiteCopyID) {
                guard let current = websiteCopyID else { return }
                do { try await Task.sleep(for: .milliseconds(1600)) } catch { return }
                if websiteCopyID == current { websiteCopyID = nil }
            }
        }
    }

    private func linkIcon(_ name: String) -> some View {
        Image(systemName: name)
            .font(.body.weight(.medium))
            .foregroundStyle(Palette.accent)
            .frame(width: 30, height: 30)
            .background(Palette.controlFill, in: .rect(cornerRadius: CornerRadius.sm))
            .accessibilityHidden(true)
    }

    private func siteURL(_ raw: String) -> URL? {
        guard let url = URL(string: raw), let scheme = url.scheme?.lowercased(),
              ["https", "http"].contains(scheme), url.host != nil, url.user == nil, url.password == nil else { return nil }
        return url
    }

    private var divider: some View { Divider().padding(.leading, Spacing.lg) }

    private func loadFolders() async {
        do { folders = try await vault.folders(); foldersAvailable = true }
        catch { foldersAvailable = false }
    }

    private func update(_ change: @escaping (inout PlaintextCipher) -> Void) {
        guard let id = cipher.id else { return }
        perform {
            var latest = try await vault.cipher(id: id)
            change(&latest)
            try await vault.updateCipher(id: id, latest)
            model.replaceCipher(latest)
            onChanged()
        }
    }

    private func copyValue(_ value: String) {
        Clipboard.copy(value)
        if let id = cipher.id { Task { await vault.recordUse(id: id) } }
    }

    private func clone() {
        guard editable, cipher.organizationID == nil else { return }
        var copy = cipher
        copy.id = nil
        copy.name += " 副本"
        copy.protectedCipherKey = nil
        copy.favorite = false
        copy.revisionDate = nil
        copy.creationDate = nil
        copy.login?.fido2Credentials = []
        let duplicate = copy
        perform {
            let id = try await vault.createCipher(duplicate)
            onChanged()
            onSelectClone?(id)
            feedback?.show("已克隆条目")
        }
    }

    private enum StatusChange { case trash, archive, restore, unarchive, delete }

    private func changeStatus(_ change: StatusChange) {
        guard let id = cipher.id else { return }
        perform {
            switch change {
            case .trash:
                try await vault.trashCipher(id: id)
                feedback?.show("已移到回收站") { try await vault.restoreCipher(id: id); onChanged() }
            case .archive:
                try await vault.archiveCipher(id: id)
                feedback?.show("已归档") { try await vault.unarchiveCipher(id: id); onChanged() }
            case .restore:
                try await vault.restoreCipher(id: id)
                feedback?.show("已恢复")
            case .unarchive:
                try await vault.unarchiveCipher(id: id)
                feedback?.show("已取消归档")
            case .delete:
                let count = try await TrashRemovalBatch(ids: [id]).perform { try await vault.permanentlyDeleteCipher(id: $0) }
                feedback?.show(TrashRemovalBatch.receipt(for: count))
            }
            editing = false
            onChanged()
            if !isSplitDetail { dismiss() }
        }
    }

    private func perform(_ action: @escaping @MainActor () async throws -> Void) {
        guard !working else { return }
        working = true
        Task {
            defer { working = false }
            do { try await action() }
            catch let failure as TrashRemovalBatch.Failure { errorMessage = failure.message; onChanged() }
            catch { errorMessage = "无法更新条目，请检查连接后重试。" }
        }
    }
}

private struct DetailField: Identifiable {
    let id: String
    let title: String
    let value: String?
    let secret: Bool

    init(_ id: String, _ title: String, _ value: String?, secret: Bool = false) {
        self.id = id
        self.title = title
        self.value = value?.isEmpty == false ? value : nil
        self.secret = secret
    }
}

@available(iOS 27.0, *)
private struct DetailCopyRow: View {
    let field: DetailField
    let copy: (String) -> Void
    var copiedExternally = false
    @State private var revealed = false

    var body: some View {
        if let value = field.value {
            HStack(spacing: 0) {
                InlineCopyButton(action: { copy(value) }) { copied in
                    HStack {
                        VStack(alignment: .leading, spacing: Spacing.xxs) {
                            Text(field.title).font(.footnote).foregroundStyle(.secondary)
                            if field.secret && !revealed {
                                Text(verbatim: "••••••••••••").font(Typography.secretValue)
                            } else if field.id == "password" {
                                ColoredSecretText(value).font(Typography.secretValue).privacySensitive()
                            } else {
                                Text(verbatim: value).font(field.secret ? Typography.secretValue : .body)
                                    .privacySensitive()
                            }
                        }
                        .multilineTextAlignment(.leading)
                        Spacer(minLength: Spacing.xs)
                        if copied || copiedExternally { InlineCopyIndicator() }
                    }
                    .padding(.leading, Spacing.lg).padding(.trailing, field.secret ? 0 : Spacing.lg)
                    .padding(.vertical, Spacing.sm).frame(minHeight: 66).contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("拷贝\(field.title)")
                .accessibilityHint(Text(verbatim: field.secret ? (revealed ? value : "已隐藏，可使用显示按钮查看") : value))
                .accessibilityIdentifier(field.id == "password" ? "item.copyPassword" : "item.copy.\(field.id)")
                if field.secret {
                    VaultFieldButton(title: revealed ? "隐藏\(field.title)" : "显示\(field.title)", systemImage: revealed ? "eye.slash" : "eye") {
                        revealed.toggle()
                    }
                    .accessibilityIdentifier(field.id == "password" ? "item.revealPassword" : "item.reveal.\(field.id)")
                    .tint(Palette.secondaryText)
                    .padding(.trailing, Spacing.xs)
                }
            }
        }
    }
}

private extension String {
    var nonblank: String? { trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : self }
}
