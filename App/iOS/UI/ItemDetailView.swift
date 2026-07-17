import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels
import Generators

@available(iOS 27.0, *)
public struct ItemDetailView: View {
    @State private var model: ItemDetailModel
    private let sourceCipher: PlaintextCipher
    private let vault: VaultService
    private let onChanged: () -> Void

    @State private var showingEdit = false
    @State private var toastMessage: String?
    @State private var toastTask: Task<Void, Never>?
    @State private var revealCardNumber = false
    @State private var revealCardCode = false
    @State private var revealSSN = false
    @State private var revealPassportNumber = false
    @State private var revealLicenseNumber = false
    @State private var revealPrivateKey = false

    public init(model: ItemDetailModel, vault: VaultService, onChanged: @escaping () -> Void) {
        _model = State(initialValue: model)
        self.sourceCipher = model.cipher
        self.vault = vault
        self.onChanged = onChanged
    }

    private var cipher: PlaintextCipher { model.cipher }

    private var supportsEditing: Bool {
        if case .unknown = CipherType(rawValue: cipher.type) { return false }
        return true
    }

    public var body: some View {
        ScrollView {
            LazyVStack(spacing: Spacing.lg) {
                header
                typeSpecificContent

                if !cipher.fields.isEmpty {
                    customFieldsCard
                }

                if let notes = cipher.notes.nonEmpty {
                    notesCard(notes)
                }

                securityStatusCard
            }
            .padding(.horizontal, Spacing.lg)
            .padding(.vertical, Spacing.sm)
        }
        .background(Palette.groupedBackground)
        .scrollEdgeEffectStyle(.soft, for: .all)
        .navigationTitle(cipher.openVaultName)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if supportsEditing {
                    Button("编辑") { showingEdit = true }
                        .fontWeight(.semibold)
                }
            }
        }
        .sheet(isPresented: $showingEdit) {
            NavigationStack {
                ItemEditView(vault: vault, existing: cipher) { id in
                    showingEdit = false
                    refresh(id: id)
                }
            }
            .presentationDetents([.large])
            .presentationDragIndicator(.visible)
        }
        .copyToast(toastMessage)
        .onDisappear { toastTask?.cancel() }
        .onChange(of: sourceCipher) { _, updated in
            model.replaceCipher(updated)
            resetSensitiveRevealState()
        }
    }

    @ViewBuilder
    private var typeSpecificContent: some View {
        switch CipherType(rawValue: cipher.type) {
        case .login:
            if let login = cipher.login {
                credentialsCard(login)
                if !login.uris.isEmpty { websitesCard(login.uris) }
            }
        case .secureNote:
            EmptyView()
        case .card:
            if let card = cipher.card { cardDetailsCard(card) }
        case .identity:
            if let identity = cipher.identity { identityDetails(identity) }
        case .sshKey:
            if let sshKey = cipher.sshKey { sshKeyCard(sshKey) }
        case .unknown:
            OpenVaultCard {
                Label("此版本无法显示该条目类型的专用字段。",
                      systemImage: "questionmark.folder")
                    .foregroundStyle(Palette.secondaryText)
            }
        }
    }

    private var header: some View {
        VStack(spacing: Spacing.sm) {
            BrandBadge(cipher.openVaultName, diameter: 60)
            Text(cipher.openVaultName)
                .font(.title2.bold())
                .multilineTextAlignment(.center)
            Text(headerSubtitle)
                .font(.subheadline)
                .foregroundStyle(Palette.secondaryText)
                .lineLimit(2)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, Spacing.sm)
    }

    private var headerSubtitle: String {
        if let host = cipher.login?.uris.first.flatMap({ URL(string: $0.uri)?.host }), !host.isEmpty {
            return "\(cipher.openVaultKindLabel) · \(host)"
        }
        return cipher.openVaultKindLabel
    }

    private func credentialsCard(_ login: PlaintextCipher.Login) -> some View {
        OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                if let username = login.username.nonEmpty {
                    fieldRow(label: "用户名", value: username) {
                        Clipboard.copy(username)
                        showToast("已拷贝用户名")
                    }
                }

                if login.username.nonEmpty != nil, login.password.nonEmpty != nil {
                    rowDivider
                }

                if let password = login.password.nonEmpty {
                    passwordRow(password)
                }

                if (login.username.nonEmpty != nil || login.password.nonEmpty != nil),
                   model.hasTOTP {
                    rowDivider
                }

                if let configuration = model.totpConfiguration {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        totpRow(configuration, at: context.date)
                    }
                }
            }
        }
    }

    private func cardDetailsCard(_ card: PlaintextCipher.Card) -> some View {
        OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                optionalFieldRow("持卡人", value: card.cardholderName)
                dividerIfNeeded(before: card.brand, after: card.cardholderName)
                optionalFieldRow("品牌", value: card.brand)
                if card.number.nonEmpty != nil, card.cardholderName.nonEmpty != nil || card.brand.nonEmpty != nil {
                    rowDivider
                }
                if let number = card.number.nonEmpty {
                    sensitiveRow(label: "卡号", value: number, isRevealed: $revealCardNumber)
                }
                if card.expMonth.nonEmpty != nil || card.expYear.nonEmpty != nil {
                    if card.number.nonEmpty != nil || card.cardholderName.nonEmpty != nil || card.brand.nonEmpty != nil {
                        rowDivider
                    }
                    fieldRow(label: "有效期", value: expiration(card)) {
                        Clipboard.copy(expiration(card))
                        showToast("已拷贝有效期")
                    }
                }
                if let code = card.code.nonEmpty {
                    rowDivider
                    sensitiveRow(label: "安全码", value: code, isRevealed: $revealCardCode)
                }
            }
        }
    }

    @ViewBuilder
    private func identityDetails(_ identity: PlaintextCipher.Identity) -> some View {
        let identityValues: [(String, String?)] = [
            ("称谓", identity.title), ("名字", identity.firstName),
            ("中间名", identity.middleName), ("姓氏", identity.lastName),
            ("用户名", identity.username), ("公司", identity.company),
            ("邮箱", identity.email), ("电话", identity.phone)
        ]
        valuesCard(identityValues)

        let addressValues: [(String, String?)] = [
            ("地址 1", identity.address1), ("地址 2", identity.address2),
            ("地址 3", identity.address3), ("城市", identity.city),
            ("省 / 州", identity.state), ("邮政编码", identity.postalCode),
            ("国家或地区", identity.country)
        ]
        if addressValues.contains(where: { $0.1.nonEmpty != nil }) {
            valuesCard(addressValues)
        }

        if identity.ssn.nonEmpty != nil || identity.passportNumber.nonEmpty != nil
            || identity.licenseNumber.nonEmpty != nil {
            OpenVaultCard(padding: 0) {
                VStack(spacing: 0) {
                    if let value = identity.ssn.nonEmpty {
                        sensitiveRow(label: "社会安全号码", value: value, isRevealed: $revealSSN)
                    }
                    if let value = identity.passportNumber.nonEmpty {
                        if identity.ssn.nonEmpty != nil { rowDivider }
                        sensitiveRow(label: "护照号码", value: value,
                                     isRevealed: $revealPassportNumber)
                    }
                    if let value = identity.licenseNumber.nonEmpty {
                        if identity.ssn.nonEmpty != nil || identity.passportNumber.nonEmpty != nil {
                            rowDivider
                        }
                        sensitiveRow(label: "证件号码", value: value,
                                     isRevealed: $revealLicenseNumber)
                    }
                }
            }
        }
    }

    private func sshKeyCard(_ sshKey: PlaintextCipher.SshKey) -> some View {
        OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                if let privateKey = sshKey.privateKey.nonEmpty {
                    sensitiveRow(label: "私钥", value: privateKey,
                                 isRevealed: $revealPrivateKey, allowsMultipleLines: true)
                }
                if let publicKey = sshKey.publicKey.nonEmpty {
                    if sshKey.privateKey.nonEmpty != nil { rowDivider }
                    fieldRow(label: "公钥", value: publicKey, allowsMultipleLines: true) {
                        Clipboard.copy(publicKey)
                        showToast("已拷贝公钥")
                    }
                }
                if let fingerprint = sshKey.keyFingerprint.nonEmpty {
                    if sshKey.privateKey.nonEmpty != nil || sshKey.publicKey.nonEmpty != nil { rowDivider }
                    fieldRow(label: "指纹", value: fingerprint) {
                        Clipboard.copy(fingerprint)
                        showToast("已拷贝指纹")
                    }
                }
            }
        }
    }

    private var customFieldsCard: some View {
        OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                ForEach(Array(cipher.fields.enumerated()), id: \.offset) { index, field in
                    let label = field.name.nonEmpty ?? "自定义字段 \(index + 1)"
                    if FieldType(rawValue: field.type) == .hidden, let value = field.value.nonEmpty {
                        SensitiveFieldRow(label: label, value: value) {
                            Clipboard.copy(value)
                            showToast("已拷贝\(label)")
                        }
                    } else if let value = field.value.nonEmpty {
                        fieldRow(label: label, value: value) {
                            Clipboard.copy(value)
                            showToast("已拷贝\(label)")
                        }
                    }
                    if index < cipher.fields.count - 1 { rowDivider }
                }
            }
        }
    }

    private func valuesCard(_ values: [(String, String?)]) -> some View {
        let present = values.compactMap { label, value in value.nonEmpty.map { (label, $0) } }
        return OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                ForEach(Array(present.enumerated()), id: \.offset) { index, entry in
                    fieldRow(label: entry.0, value: entry.1) {
                        Clipboard.copy(entry.1)
                        showToast("已拷贝\(entry.0)")
                    }
                    if index < present.count - 1 { rowDivider }
                }
            }
        }
    }

    @ViewBuilder
    private func optionalFieldRow(_ label: String, value: String?) -> some View {
        if let value = value.nonEmpty {
            fieldRow(label: label, value: value) {
                Clipboard.copy(value)
                showToast("已拷贝\(label)")
            }
        }
    }

    @ViewBuilder
    private func dividerIfNeeded(before: String?, after: String?) -> some View {
        if before.nonEmpty != nil, after.nonEmpty != nil { rowDivider }
    }

    private func fieldRow(label: String, value: String, allowsMultipleLines: Bool = false,
                          onCopy: @escaping () -> Void) -> some View {
        HStack(spacing: Spacing.md) {
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text(label)
                    .font(Typography.fieldLabel)
                    .foregroundStyle(Palette.secondaryText)
                Text(value)
                    .font(.body)
                    .foregroundStyle(Palette.primaryText)
                    .textSelection(.enabled)
                    .lineLimit(allowsMultipleLines ? 8 : 1)
                    .truncationMode(.middle)
                    .privacySensitive()
            }
            Spacer(minLength: Spacing.sm)
            Button(action: onCopy) { Image(systemName: "doc.on.doc") }
                .buttonStyle(.plain)
                .foregroundStyle(Palette.accent)
                .frame(width: 44, height: 44)
                .accessibilityLabel("复制\(label)")
        }
        .padding(.leading, Spacing.lg)
        .padding(.trailing, Spacing.sm)
        .padding(.vertical, allowsMultipleLines ? Spacing.sm : 0)
        .frame(minHeight: 60)
    }

    private func sensitiveRow(label: String, value: String, isRevealed: Binding<Bool>,
                              allowsMultipleLines: Bool = false) -> some View {
        HStack(spacing: Spacing.sm) {
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text(label)
                    .font(Typography.fieldLabel)
                    .foregroundStyle(Palette.secondaryText)
                Group {
                    if isRevealed.wrappedValue {
                        Text(value).textSelection(.enabled)
                    } else {
                        Text("••••••••••••••••")
                    }
                }
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(Palette.primaryText)
                    .lineLimit(isRevealed.wrappedValue && allowsMultipleLines ? 8 : 1)
                    .truncationMode(.middle)
                    .privacySensitive()
            }
            Spacer(minLength: 0)
            Button { isRevealed.wrappedValue.toggle() } label: {
                Image(systemName: isRevealed.wrappedValue ? "eye.slash" : "eye")
            }
            .buttonStyle(.plain)
            .foregroundStyle(Palette.accent)
            .frame(width: 44, height: 44)
            .accessibilityLabel(isRevealed.wrappedValue ? "隐藏\(label)" : "显示\(label)")
            Button {
                Clipboard.copy(value)
                showToast("已拷贝\(label)")
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.plain)
            .foregroundStyle(Palette.accent)
            .frame(width: 44, height: 44)
            .accessibilityLabel("复制\(label)")
        }
        .padding(.leading, Spacing.lg)
        .padding(.trailing, Spacing.sm)
        .padding(.vertical, allowsMultipleLines ? Spacing.sm : 0)
        .frame(minHeight: 64)
    }

    private func passwordRow(_ password: String) -> some View {
        HStack(spacing: Spacing.sm) {
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text("密码")
                    .font(Typography.fieldLabel)
                    .foregroundStyle(Palette.secondaryText)
                Text(model.revealPassword ? password : "••••••••••••••••")
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(Palette.primaryText)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .privacySensitive()
            }
            Spacer(minLength: 0)
            Button { model.toggleReveal() } label: {
                Image(systemName: model.revealPassword ? "eye.slash" : "eye")
            }
            .buttonStyle(.plain)
            .foregroundStyle(Palette.accent)
            .frame(width: 44, height: 44)
            .accessibilityLabel(model.revealPassword ? "隐藏密码" : "显示密码")
            Button {
                Clipboard.copy(password)
                showToast("已拷贝密码")
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.plain)
            .foregroundStyle(Palette.accent)
            .frame(width: 44, height: 44)
            .accessibilityLabel("复制密码")
        }
        .padding(.leading, Spacing.lg)
        .padding(.trailing, Spacing.sm)
        .frame(minHeight: 64)
    }

    private func totpRow(_ configuration: TOTPConfiguration, at date: Date) -> some View {
        let raw = TOTP.code(for: configuration, at: date)
        let code = OTPRingMath.formatCode(raw)
        let seconds = TOTP.secondsRemaining(for: configuration, at: date)
        let progress = OTPRingMath.progress(secondsRemaining: seconds, period: configuration.period)

        return HStack(spacing: Spacing.md) {
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text("验证码")
                    .font(Typography.fieldLabel)
                    .foregroundStyle(Palette.secondaryText)
                HStack(spacing: Spacing.md) {
                    Text(code)
                        .font(.system(size: 19, weight: .medium, design: .monospaced))
                        .monospacedDigit()
                        .privacySensitive()
                    CountdownRing(progress: progress, size: 22)
                }
            }
            Spacer()
            Button {
                Clipboard.copy(raw)
                showToast("已拷贝验证码")
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.plain)
            .foregroundStyle(Palette.accent)
            .frame(width: 44, height: 44)
            .accessibilityLabel("复制验证码")
        }
        .padding(.leading, Spacing.lg)
        .padding(.trailing, Spacing.sm)
        .frame(minHeight: 68)
    }

    private func websitesCard(_ uris: [PlaintextCipher.Uri]) -> some View {
        OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                ForEach(Array(uris.enumerated()), id: \.offset) { index, entry in
                    fieldRow(label: index == 0 ? "网站" : "网站 \(index + 1)", value: entry.uri) {
                        Clipboard.copy(entry.uri)
                        showToast("已拷贝网站")
                    }
                    if index < uris.count - 1 { rowDivider }
                }
            }
        }
    }

    private func notesCard(_ notes: String) -> some View {
        OpenVaultCard {
            VStack(alignment: .leading, spacing: Spacing.sm) {
                Text("备注")
                    .font(Typography.fieldLabel)
                    .foregroundStyle(Palette.secondaryText)
                Text(notes)
                    .font(.body)
                    .foregroundStyle(Palette.primaryText)
                    .textSelection(.enabled)
                    .privacySensitive()
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private var securityStatusCard: some View {
        OpenVaultCard {
            HStack(spacing: Spacing.md) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.title3)
                    .foregroundStyle(Palette.accent)
                    .frame(width: 34, height: 34)
                    .background(Palette.accent.opacity(0.12), in: Circle())
                VStack(alignment: .leading, spacing: Spacing.xxs) {
                    Text("安全状态").font(.headline)
                    Text("此版本尚未接入泄露检测，不对该条目作风险结论。")
                        .font(.caption)
                        .foregroundStyle(Palette.secondaryText)
                }
            }
        }
    }

    private var rowDivider: some View {
        Divider().padding(.leading, Spacing.lg)
    }

    private func expiration(_ card: PlaintextCipher.Card) -> String {
        [card.expMonth.nonEmpty, card.expYear.nonEmpty].compactMap { $0 }.joined(separator: " / ")
    }

    private func refresh(id: String) {
        Task {
            if let refreshed = try? await vault.cipher(id: id) {
                model.replaceCipher(refreshed)
                resetSensitiveRevealState()
            }
            onChanged()
        }
    }

    private func resetSensitiveRevealState() {
        revealCardNumber = false
        revealCardCode = false
        revealSSN = false
        revealPassportNumber = false
        revealLicenseNumber = false
        revealPrivateKey = false
    }

    private func showToast(_ message: String) {
        toastTask?.cancel()
        toastMessage = message
        toastTask = Task {
            try? await Task.sleep(for: .seconds(1.6))
            guard !Task.isCancelled else { return }
            toastMessage = nil
        }
    }
}

@available(iOS 27.0, *)
private struct SensitiveFieldRow: View {
    let label: String
    let value: String
    let onCopy: () -> Void
    @State private var isRevealed = false

    init(label: String, value: String, onCopy: @escaping () -> Void) {
        self.label = label
        self.value = value
        self.onCopy = onCopy
    }

    var body: some View {
        HStack(spacing: Spacing.sm) {
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text(label).font(Typography.fieldLabel).foregroundStyle(Palette.secondaryText)
                Text(isRevealed ? value : "••••••••••••••••")
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                    .privacySensitive()
            }
            Spacer()
            Button { isRevealed.toggle() } label: {
                Image(systemName: isRevealed ? "eye.slash" : "eye")
            }
            .frame(width: 44, height: 44)
            .accessibilityLabel(isRevealed ? "隐藏\(label)" : "显示\(label)")
            Button(action: onCopy) { Image(systemName: "doc.on.doc") }
                .frame(width: 44, height: 44)
                .accessibilityLabel("复制\(label)")
        }
        .buttonStyle(.plain)
        .foregroundStyle(Palette.accent)
        .padding(.leading, Spacing.lg)
        .padding(.trailing, Spacing.sm)
        .frame(minHeight: 64)
    }
}

private extension Optional where Wrapped == String {
    var nonEmpty: String? {
        guard let self else { return nil }
        let trimmed = self.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : self
    }
}
