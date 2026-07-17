import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels
import Generators

@available(macOS 27.0, *)
struct MacItemDetailView: View {
    let cipher: PlaintextCipher
    private let vault: VaultService
    private let onChanged: () -> Void

    @State private var revealPassword = false
    @State private var revealCardNumber = false
    @State private var revealCardCode = false
    @State private var revealSSN = false
    @State private var revealPassportNumber = false
    @State private var revealLicenseNumber = false
    @State private var revealPrivateKey = false
    @State private var revealedCustomFields: Set<Int> = []
    @State private var showingEdit = false
    @State private var showInspector = false
    @State private var showingDeleteConfirm = false
    @State private var copiedMessage: String?
    @State private var toastID = UUID()

    init(cipher: PlaintextCipher, vault: VaultService, onChanged: @escaping () -> Void) {
        self.cipher = cipher
        self.vault = vault
        self.onChanged = onChanged
    }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            ScrollView {
                VStack(alignment: .leading, spacing: 11) {
                    header
                    typeSpecificCards(at: context.date)

                    if !cipher.fields.isEmpty { customFieldsCard }
                    if let notes = cipher.notes?.nilIfBlank { notesCard(notes) }

                    availabilityCard
                    footer
                }
                .padding(.horizontal, 24)
                .padding(.vertical, 18)
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
            .scrollEdgeEffectStyle(.soft, for: .top)
            .background(MacOpenVaultStyle.detail)
            .overlay(alignment: .bottom) {
                if let copiedMessage {
                    GlassToast(copiedMessage)
                        .padding(.bottom, 24)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
        }
        .inspector(isPresented: $showInspector) {
            inspector.inspectorColumnWidth(min: 230, ideal: 270, max: 340)
        }
        .sheet(isPresented: $showingEdit) {
            MacItemEditView(vault: vault, existing: cipher) { _ in
                showingEdit = false
                onChanged()
            }
        }
        .confirmationDialog("删除这个条目？", isPresented: $showingDeleteConfirm,
                            titleVisibility: .visible) {
            Button("删除", role: .destructive) { deleteItem() }
            Button("取消", role: .cancel) {}
        } message: {
            Text("此操作会同步到服务器，且无法在当前版本中撤销。")
        }
        .onChange(of: cipher) { _, _ in resetRevealState() }
    }

    private var header: some View {
        HStack(spacing: 13) {
            BrandBadge(cipher.name, diameter: 50)
            VStack(alignment: .leading, spacing: 2) {
                Text(cipher.name.nilIfBlank ?? "未命名条目")
                    .font(.system(size: 20, weight: .bold))
                    .foregroundStyle(.white)
                HStack(spacing: 4) {
                    Text(detailSubtitle ?? cipher.macTypeLabel)
                    if cipher.favorite { Text("· 已置顶") }
                }
                .font(.system(size: 12))
                .foregroundStyle(MacOpenVaultStyle.secondary)
            }
            Spacer(minLength: 12)

            Button { showInspector.toggle() } label: {
                Label("信息", systemImage: "info.circle")
                    .font(.system(size: 12.5, weight: .semibold))
                    .padding(.horizontal, 4).frame(height: 30)
            }
            .buttonStyle(.glass)

            Button { showingEdit = true } label: {
                Label("编辑", systemImage: "pencil")
                    .font(.system(size: 12.5, weight: .semibold))
                    .padding(.horizontal, 4).frame(height: 30)
            }
            .buttonStyle(.glassProminent)

            Button(role: .destructive) { showingDeleteConfirm = true } label: {
                Image(systemName: "trash")
                    .font(.system(size: 12.5, weight: .semibold))
                    .frame(width: 30, height: 30)
            }
            .buttonStyle(.glass)
            .help("删除条目")
        }
        .padding(.bottom, 5)
    }

    private var detailSubtitle: String? {
        switch CipherType(rawValue: cipher.type) {
        case .login: cipher.login?.username?.nilIfBlank
        case .secureNote: nil
        case .card: cipher.card?.cardholderName?.nilIfBlank ?? cipher.card?.brand?.nilIfBlank
        case .identity:
            [cipher.identity?.firstName, cipher.identity?.middleName, cipher.identity?.lastName]
                .compactMap { $0?.nilIfBlank }.joined(separator: " ").nilIfBlank
                ?? cipher.identity?.email?.nilIfBlank
        case .sshKey: cipher.sshKey?.keyFingerprint?.nilIfBlank
        case .unknown: nil
        }
    }

    @ViewBuilder
    private func typeSpecificCards(at date: Date) -> some View {
        switch CipherType(rawValue: cipher.type) {
        case .login:
            if let login = cipher.login { loginCard(login, at: date) }
        case .secureNote:
            EmptyView()
        case .card:
            if let card = cipher.card { paymentCard(card) }
        case .identity:
            if let identity = cipher.identity { identityCards(identity) }
        case .sshKey:
            if let sshKey = cipher.sshKey { sshKeyCard(sshKey) }
        case .unknown:
            ContentUnavailableView("无法显示此类型", systemImage: "questionmark.square.dashed")
        }
    }

    private func loginCard(_ login: PlaintextCipher.Login, at date: Date) -> some View {
        fieldCard {
            VStack(spacing: 0) {
                if let username = login.username?.nilIfBlank {
                    copyField(label: "用户名", value: username, message: "已拷贝用户名")
                    fieldDivider
                }
                if let password = login.password?.nilIfBlank {
                    secretField(label: "密码", value: password, reveal: $revealPassword,
                                message: "已拷贝密码")
                    if login.totp?.nilIfBlank != nil || !login.uris.isEmpty { fieldDivider }
                }
                if let configuration = totpConfiguration(login) {
                    totpField(configuration, at: date)
                    if !login.uris.isEmpty { fieldDivider }
                }
                ForEach(Array(login.uris.enumerated()), id: \.offset) { index, uri in
                    websiteField(uri.uri)
                    if index < login.uris.count - 1 { fieldDivider }
                }
            }
        }
    }

    private func paymentCard(_ card: PlaintextCipher.Card) -> some View {
        fieldCard {
            VStack(spacing: 0) {
                optionalCopyRow(card.cardholderName, label: "持卡人")
                optionalDivider(after: card.cardholderName, before: card.brand)
                optionalCopyRow(card.brand, label: "品牌")
                if card.brand?.nilIfBlank != nil && card.number?.nilIfBlank != nil { fieldDivider }
                if let number = card.number?.nilIfBlank {
                    secretField(label: "卡号", value: number, reveal: $revealCardNumber,
                                message: "已拷贝卡号")
                }
                if card.number?.nilIfBlank != nil,
                   card.expMonth?.nilIfBlank != nil || card.expYear?.nilIfBlank != nil { fieldDivider }
                if card.expMonth?.nilIfBlank != nil || card.expYear?.nilIfBlank != nil {
                    copyField(label: "有效期", value: [card.expMonth, card.expYear]
                        .compactMap { $0?.nilIfBlank }.joined(separator: "/"), message: "已拷贝有效期")
                }
                if (card.expMonth?.nilIfBlank != nil || card.expYear?.nilIfBlank != nil),
                   card.code?.nilIfBlank != nil { fieldDivider }
                if let code = card.code?.nilIfBlank {
                    secretField(label: "安全码（CVV）", value: code, reveal: $revealCardCode,
                                message: "已拷贝安全码")
                }
            }
        }
    }

    @ViewBuilder
    private func identityCards(_ identity: PlaintextCipher.Identity) -> some View {
        identityCard(title: "姓名与联系信息", values: [
            ("称谓", identity.title), ("名字", identity.firstName),
            ("中间名", identity.middleName), ("姓氏", identity.lastName),
            ("用户名", identity.username), ("公司", identity.company),
            ("邮箱", identity.email), ("电话", identity.phone)
        ])
        identityCard(title: "地址", values: [
            ("地址 1", identity.address1), ("地址 2", identity.address2),
            ("地址 3", identity.address3), ("城市", identity.city),
            ("省/州", identity.state), ("邮编", identity.postalCode),
            ("国家/地区", identity.country)
        ])
        if identity.ssn?.nilIfBlank != nil || identity.passportNumber?.nilIfBlank != nil
            || identity.licenseNumber?.nilIfBlank != nil {
            fieldCard {
                VStack(spacing: 0) {
                    if let value = identity.ssn?.nilIfBlank {
                        secretField(label: "社会安全号", value: value, reveal: $revealSSN,
                                    message: "已拷贝社会安全号")
                    }
                    if identity.ssn?.nilIfBlank != nil && identity.passportNumber?.nilIfBlank != nil { fieldDivider }
                    if let value = identity.passportNumber?.nilIfBlank {
                        secretField(label: "护照号码", value: value, reveal: $revealPassportNumber,
                                    message: "已拷贝护照号码")
                    }
                    if identity.passportNumber?.nilIfBlank != nil && identity.licenseNumber?.nilIfBlank != nil { fieldDivider }
                    if let value = identity.licenseNumber?.nilIfBlank {
                        secretField(label: "驾照号码", value: value, reveal: $revealLicenseNumber,
                                    message: "已拷贝驾照号码")
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func identityCard(title: String, values: [(String, String?)]) -> some View {
        let present = values.compactMap { label, value in value?.nilIfBlank.map { (label, $0) } }
        if !present.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                Text(title).font(.system(size: 11.5, weight: .semibold)).foregroundStyle(.white.opacity(0.42))
                fieldCard {
                    VStack(spacing: 0) {
                        ForEach(Array(present.enumerated()), id: \.offset) { index, item in
                            copyField(label: item.0, value: item.1, message: "已拷贝\(item.0)")
                            if index < present.count - 1 { fieldDivider }
                        }
                    }
                }
            }
        }
    }

    private func sshKeyCard(_ sshKey: PlaintextCipher.SshKey) -> some View {
        fieldCard {
            VStack(spacing: 0) {
                if let value = sshKey.privateKey?.nilIfBlank {
                    secretField(label: "私钥", value: value, reveal: $revealPrivateKey,
                                message: "已拷贝私钥", multiline: true)
                }
                if sshKey.privateKey?.nilIfBlank != nil && sshKey.publicKey?.nilIfBlank != nil { fieldDivider }
                if let value = sshKey.publicKey?.nilIfBlank {
                    copyField(label: "公钥", value: value, message: "已拷贝公钥", multiline: true)
                }
                if sshKey.publicKey?.nilIfBlank != nil && sshKey.keyFingerprint?.nilIfBlank != nil { fieldDivider }
                if let value = sshKey.keyFingerprint?.nilIfBlank {
                    copyField(label: "指纹", value: value, message: "已拷贝指纹")
                }
            }
        }
    }

    private var customFieldsCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("自定义字段").font(.system(size: 11.5, weight: .semibold)).foregroundStyle(.white.opacity(0.42))
            fieldCard {
                VStack(spacing: 0) {
                    ForEach(Array(cipher.fields.enumerated()), id: \.offset) { index, field in
                        let label = field.name?.nilIfBlank ?? "字段 \(index + 1)"
                        if field.type == FieldType.hidden.rawValue, let value = field.value?.nilIfBlank {
                            secretField(label: label, value: value, reveal: customFieldBinding(index),
                                        message: "已拷贝\(label)")
                        } else if let value = field.value?.nilIfBlank {
                            copyField(label: label, value: value, message: "已拷贝\(label)")
                        } else {
                            copyField(label: label, value: "—", message: "")
                        }
                        if index < cipher.fields.count - 1 { fieldDivider }
                    }
                }
            }
        }
    }

    private func copyField(label: String, value: String, message: String,
                           multiline: Bool = false) -> some View {
        HStack(alignment: multiline ? .top : .center, spacing: 12) {
            fieldValue(label: label, value: value, multiline: multiline)
            Spacer(minLength: 8)
            if !message.isEmpty { copyButton(value, message: message, label: "拷贝\(label)") }
        }
        .padding(.horizontal, 15)
        .frame(minHeight: multiline ? 82 : 50)
    }

    @ViewBuilder
    private func optionalCopyRow(_ value: String?, label: String) -> some View {
        if let value = value?.nilIfBlank {
            copyField(label: label, value: value, message: "已拷贝\(label)")
        }
    }

    @ViewBuilder
    private func optionalDivider(after lhs: String?, before rhs: String?) -> some View {
        if lhs?.nilIfBlank != nil && rhs?.nilIfBlank != nil { fieldDivider }
    }

    private func secretField(label: String, value: String, reveal: Binding<Bool>,
                             message: String, multiline: Bool = false) -> some View {
        HStack(alignment: multiline ? .top : .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).font(.system(size: 11)).foregroundStyle(.white.opacity(0.45))
                Text(reveal.wrappedValue ? value : String(repeating: "•", count: min(max(value.count, 8), 16)))
                    .font(.system(size: 13.5, design: .monospaced))
                    .tracking(reveal.wrappedValue ? 0 : 2.5)
                    .foregroundStyle(.white.opacity(0.94))
                    .lineLimit(multiline && reveal.wrappedValue ? 8 : 1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                    .privacySensitive()
            }
            Spacer(minLength: 8)
            Button { reveal.wrappedValue.toggle() } label: {
                Image(systemName: reveal.wrappedValue ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
            .foregroundStyle(MacOpenVaultStyle.selectedBlue)
            .accessibilityLabel(reveal.wrappedValue ? "隐藏\(label)" : "显示\(label)")
            copyButton(value, message: message, label: "拷贝\(label)")
        }
        .padding(.horizontal, 15)
        .frame(minHeight: multiline ? 96 : 50)
    }

    private func totpField(_ configuration: TOTPConfiguration, at date: Date) -> some View {
        let raw = TOTP.code(for: configuration, at: date)
        let code = OTPRingMath.formatCode(raw)
        let seconds = TOTP.secondsRemaining(for: configuration, at: date)
        let progress = OTPRingMath.progress(secondsRemaining: seconds, period: configuration.period)
        return HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("验证码").font(.system(size: 11)).foregroundStyle(.white.opacity(0.45))
                HStack(spacing: 9) {
                    Text(code)
                        .font(.system(size: 15, weight: .medium, design: .monospaced))
                        .tracking(1.5).monospacedDigit().foregroundStyle(.white.opacity(0.94))
                        .contentTransition(.numericText()).privacySensitive()
                    CountdownRing(progress: progress, size: 17, lineWidth: 2.4,
                                  tint: MacOpenVaultStyle.totp)
                }
            }
            Spacer(minLength: 8)
            copyButton(raw, message: "已拷贝验证码", label: "拷贝验证码")
        }
        .padding(.horizontal, 15).frame(minHeight: 50)
    }

    private func websiteField(_ value: String) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("网站").font(.system(size: 11)).foregroundStyle(.white.opacity(0.45))
                if let url = webURL(value) {
                    Link(value, destination: url)
                        .font(.system(size: 13.5)).foregroundStyle(Color(red: 121 / 255, green: 186 / 255, blue: 1))
                        .lineLimit(1).truncationMode(.middle)
                } else {
                    Text(value).font(.system(size: 13.5)).foregroundStyle(.white.opacity(0.9))
                        .lineLimit(1).truncationMode(.middle)
                }
            }
            Spacer(minLength: 8)
            copyButton(value, message: "已拷贝网站", label: "拷贝网站")
        }
        .padding(.horizontal, 15).frame(minHeight: 50)
    }

    private func notesCard(_ notes: String) -> some View {
        OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 15) {
            VStack(alignment: .leading, spacing: 4) {
                Text("备注").font(.system(size: 11)).foregroundStyle(.white.opacity(0.45))
                Text(notes).font(.system(size: 12.5)).lineSpacing(3)
                    .foregroundStyle(.white.opacity(0.84)).textSelection(.enabled)
            }
        }
        .overlay { cardStroke }
    }

    private var availabilityCard: some View {
        OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 0) {
            HStack(spacing: 10) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 17)).foregroundStyle(.white.opacity(0.52)).frame(width: 24, height: 24)
                Text("尚未运行安全检查").font(.system(size: 13.5)).foregroundStyle(.white.opacity(0.88))
                Spacer()
                Text("当前服务层未提供泄露报告").font(.system(size: 12)).foregroundStyle(.white.opacity(0.42))
            }
            .padding(.horizontal, 15).frame(minHeight: 46)
        }
        .overlay { cardStroke }
    }

    private var footer: some View {
        HStack {
            Text("端到端加密 · \(cipher.macTypeLabel)")
            Spacer()
            if let id = cipher.id {
                Text(id).lineLimit(1).truncationMode(.middle).frame(maxWidth: 180)
            }
        }
        .font(.system(size: 11)).foregroundStyle(.white.opacity(0.36)).padding(.top, 4)
    }

    private var inspector: some View {
        Form {
            Section("元数据") {
                LabeledContent("类型", value: cipher.macTypeLabel)
                LabeledContent("置顶", value: cipher.favorite ? "是" : "否")
                LabeledContent("再次验证", value: cipher.reprompt == 0 ? "关闭" : "开启")
                if let id = cipher.id {
                    LabeledContent("条目 ID") {
                        Text(id).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                    }
                }
                if let organizationID = cipher.organizationID {
                    LabeledContent("组织 ID", value: organizationID)
                }
            }
            if let login = cipher.login {
                Section("登录安全") {
                    LabeledContent("Passkey", value: "\(login.fido2Credentials.count)")
                    if let revised = login.passwordRevisionDate {
                        LabeledContent("密码修改", value: revised.formatted(date: .abbreviated, time: .shortened))
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    private func fieldCard<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 0, content: content)
            .overlay { cardStroke }
    }

    private var fieldDivider: some View {
        Divider().overlay(MacOpenVaultStyle.hairline).padding(.leading, 15)
    }

    private var cardStroke: some View {
        RoundedRectangle(cornerRadius: CornerRadius.macCard, style: .continuous)
            .stroke(.white.opacity(0.07), lineWidth: 0.5)
    }

    private func fieldValue(label: String, value: String, multiline: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.system(size: 11)).foregroundStyle(.white.opacity(0.45))
            Text(value).font(.system(size: 13.5, design: multiline ? .monospaced : .default))
                .foregroundStyle(.white.opacity(0.94)).lineLimit(multiline ? 8 : 1)
                .truncationMode(.middle).textSelection(.enabled)
        }
    }

    private func copyButton(_ value: String, message: String, label: String) -> some View {
        Button { copy(value, message: message) } label: { Image(systemName: "doc.on.doc") }
            .buttonStyle(.borderless).foregroundStyle(MacOpenVaultStyle.selectedBlue)
            .help(label).accessibilityLabel(label)
    }

    private func customFieldBinding(_ index: Int) -> Binding<Bool> {
        Binding(
            get: { revealedCustomFields.contains(index) },
            set: { revealed in
                if revealed { revealedCustomFields.insert(index) }
                else { revealedCustomFields.remove(index) }
            }
        )
    }

    private func totpConfiguration(_ login: PlaintextCipher.Login) -> TOTPConfiguration? {
        guard let raw = login.totp?.nilIfBlank else { return nil }
        return try? TOTP.configuration(from: raw)
    }

    private func webURL(_ value: String) -> URL? {
        if let url = URL(string: value), let scheme = url.scheme,
           ["http", "https"].contains(scheme.lowercased()) { return url }
        return URL(string: "https://\(value)")
    }

    private func copy(_ value: String, message: String) {
        MacClipboard.copy(value)
        let id = UUID()
        toastID = id
        withAnimation(.snappy(duration: 0.25)) { copiedMessage = message }
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(1.6))
            guard toastID == id else { return }
            withAnimation(.easeOut(duration: 0.2)) { copiedMessage = nil }
        }
    }

    private func deleteItem() {
        guard let id = cipher.id else { return }
        Task {
            do {
                try await vault.deleteCipher(id: id)
                onChanged()
            } catch {
                withAnimation(.snappy) { copiedMessage = "无法删除条目" }
            }
        }
    }

    private func resetRevealState() {
        revealPassword = false; revealCardNumber = false; revealCardCode = false
        revealSSN = false; revealPassportNumber = false; revealLicenseNumber = false
        revealPrivateKey = false; revealedCustomFields.removeAll()
    }
}
