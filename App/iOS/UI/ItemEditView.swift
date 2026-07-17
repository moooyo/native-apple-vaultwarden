import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels

@available(iOS 27.0, *)
public struct ItemEditView: View {
    private let vault: VaultService
    private let existing: PlaintextCipher?
    private let onSaved: (String) -> Void

    @Environment(\.dismiss) private var dismiss

    @State private var type: Int
    @State private var name: String
    @State private var loginDraft: LoginDraft
    @State private var cardDraft: CardDraft
    @State private var identityDraft: IdentityDraft
    @State private var sshKeyDraft: SshKeyDraft
    @State private var notes: String
    @State private var favorite: Bool
    @State private var generator = GeneratorModel()

    @State private var revealPassword = false
    @State private var revealTOTP = false
    @State private var revealCardNumber = false
    @State private var revealCardCode = false
    @State private var revealSSN = false
    @State private var revealPassportNumber = false
    @State private var revealLicenseNumber = false
    @State private var revealPrivateKey = false
    @State private var isSaving = false
    @State private var errorMessage: String?

    public init(vault: VaultService, existing: PlaintextCipher? = nil,
                onSaved: @escaping (String) -> Void) {
        self.vault = vault
        self.existing = existing
        self.onSaved = onSaved
        _type = State(initialValue: existing?.type ?? CipherType.login.rawValue)
        _name = State(initialValue: existing?.name ?? "")
        _loginDraft = State(initialValue: LoginDraft(existing?.login))
        _cardDraft = State(initialValue: CardDraft(existing?.card))
        _identityDraft = State(initialValue: IdentityDraft(existing?.identity))
        _sshKeyDraft = State(initialValue: SshKeyDraft(existing?.sshKey))
        _notes = State(initialValue: existing?.notes ?? "")
        _favorite = State(initialValue: existing?.favorite ?? false)
    }

    private var selectedType: CipherType { CipherType(rawValue: type) }

    private var canSave: Bool {
        guard case .unknown = selectedType else {
            return !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !isSaving
        }
        return false
    }

    public var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: Spacing.md) {
                typeCard

                groupTitle("基本信息")
                OpenVaultCard(padding: 0) {
                    VStack(spacing: 0) {
                        labeledField("名称", text: $name, contentType: .name)
                        rowDivider
                        Toggle(isOn: $favorite) {
                            Label("置顶", systemImage: "star")
                        }
                        .padding(.horizontal, Spacing.lg)
                        .frame(minHeight: 54)
                    }
                }

                typeSpecificFields

                groupTitle("备注")
                OpenVaultCard {
                    TextField("添加备注…", text: $notes, axis: .vertical)
                        .lineLimit(4...10)
                        .privacySensitive()
                        .frame(minHeight: 110, alignment: .top)
                }

                if !existingFieldsDescription.isEmpty {
                    Text(existingFieldsDescription)
                        .font(.caption)
                        .foregroundStyle(Palette.secondaryText)
                        .padding(.horizontal, Spacing.lg)
                }

                if let errorMessage {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .font(.subheadline)
                        .foregroundStyle(Palette.danger)
                        .padding(.horizontal, Spacing.lg)
                }
            }
            .padding(.horizontal, Spacing.lg)
            .padding(.vertical, Spacing.sm)
        }
        .background(Palette.groupedBackground)
        .navigationTitle(existing == nil ? "新建条目" : "编辑条目")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("取消") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                if isSaving {
                    ProgressView()
                } else {
                    Button("存储") { save() }
                        .fontWeight(.semibold)
                        .disabled(!canSave)
                }
            }
        }
    }

    private var typeCard: some View {
        OpenVaultCard {
            HStack {
                Text("类型")
                Spacer()
                Picker("类型", selection: $type) {
                    Text("登录").tag(CipherType.login.rawValue)
                    Text("安全笔记").tag(CipherType.secureNote.rawValue)
                    Text("银行卡").tag(CipherType.card.rawValue)
                    Text("身份").tag(CipherType.identity.rawValue)
                    Text("SSH 密钥").tag(CipherType.sshKey.rawValue)
                }
                .labelsHidden()
                .pickerStyle(.menu)
                .disabled(existing != nil)
            }
        }
    }

    @ViewBuilder
    private var typeSpecificFields: some View {
        switch selectedType {
        case .login:
            loginFields
        case .secureNote:
            EmptyView()
        case .card:
            cardFields
        case .identity:
            identityFields
        case .sshKey:
            sshKeyFields
        case .unknown:
            OpenVaultCard {
                Label("此版本无法编辑该条目类型。", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(Palette.warning)
            }
        }
    }

    private var loginFields: some View {
        Group {
            groupTitle("登录凭据")
            OpenVaultCard(padding: 0) {
                VStack(spacing: 0) {
                    labeledField("用户名", text: $loginDraft.username, contentType: .username,
                                 capitalization: .never)
                    rowDivider
                    secretField("密码", text: $loginDraft.password, isRevealed: $revealPassword,
                                contentType: .password, trailingAction: {
                        generator.regenerate()
                        loginDraft.password = generator.generated
                    })
                    rowDivider
                    secretField("验证器密钥", text: $loginDraft.totp, isRevealed: $revealTOTP)
                }
            }

            groupTitle("网站")
            websitesCard
        }
    }

    private var websitesCard: some View {
        OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                ForEach(loginDraft.uris.indices, id: \.self) { index in
                    HStack(spacing: Spacing.sm) {
                        VStack(alignment: .leading, spacing: Spacing.xxs) {
                            Text(index == 0 ? "网站" : "网站 \(index + 1)")
                                .font(Typography.fieldLabel)
                                .foregroundStyle(Palette.secondaryText)
                            TextField("https://example.com", text: $loginDraft.uris[index].uri)
                                .textContentType(.URL)
                                .keyboardType(.URL)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                        }
                        if loginDraft.uris.count > 1 {
                            Button(role: .destructive) { loginDraft.uris.remove(at: index) } label: {
                                Image(systemName: "minus.circle.fill")
                            }
                            .buttonStyle(.plain)
                            .frame(width: 44, height: 44)
                            .accessibilityLabel("删除网站")
                        }
                    }
                    .padding(.horizontal, Spacing.lg)
                    .padding(.vertical, Spacing.sm)
                    .frame(minHeight: 66)
                    if index < loginDraft.uris.count { rowDivider }
                }

                Button { loginDraft.uris.append(.init(uri: "")) } label: {
                    Label("添加网站", systemImage: "plus.circle.fill")
                        .frame(maxWidth: .infinity, minHeight: 52, alignment: .leading)
                }
                .buttonStyle(.plain)
                .foregroundStyle(Palette.primaryText)
                .tint(Palette.success)
                .padding(.horizontal, Spacing.lg)
            }
        }
    }

    private var cardFields: some View {
        Group {
            groupTitle("银行卡")
            OpenVaultCard(padding: 0) {
                VStack(spacing: 0) {
                    labeledField("持卡人", text: $cardDraft.cardholderName, contentType: .name)
                    rowDivider
                    labeledField("品牌", text: $cardDraft.brand)
                    rowDivider
                    secretField("卡号", text: $cardDraft.number, isRevealed: $revealCardNumber,
                                keyboard: .numberPad)
                    rowDivider
                    HStack(spacing: Spacing.lg) {
                        compactField("月份", text: $cardDraft.expMonth, keyboard: .numberPad)
                        compactField("年份", text: $cardDraft.expYear, keyboard: .numberPad)
                    }
                    .padding(.horizontal, Spacing.lg)
                    .frame(minHeight: 66)
                    rowDivider
                    secretField("安全码", text: $cardDraft.code, isRevealed: $revealCardCode,
                                keyboard: .numberPad)
                }
            }
        }
    }

    private var identityFields: some View {
        Group {
            groupTitle("姓名")
            OpenVaultCard(padding: 0) {
                VStack(spacing: 0) {
                    labeledField("称谓", text: $identityDraft.title)
                    rowDivider
                    labeledField("名字", text: $identityDraft.firstName, contentType: .givenName)
                    rowDivider
                    labeledField("中间名", text: $identityDraft.middleName, contentType: .middleName)
                    rowDivider
                    labeledField("姓氏", text: $identityDraft.lastName, contentType: .familyName)
                }
            }

            groupTitle("联系信息")
            OpenVaultCard(padding: 0) {
                VStack(spacing: 0) {
                    labeledField("用户名", text: $identityDraft.username, contentType: .username,
                                 capitalization: .never)
                    rowDivider
                    labeledField("公司", text: $identityDraft.company, contentType: .organizationName)
                    rowDivider
                    labeledField("邮箱", text: $identityDraft.email, contentType: .emailAddress,
                                 capitalization: .never, keyboard: .emailAddress)
                    rowDivider
                    labeledField("电话", text: $identityDraft.phone, contentType: .telephoneNumber,
                                 keyboard: .phonePad)
                }
            }

            groupTitle("地址")
            OpenVaultCard(padding: 0) {
                VStack(spacing: 0) {
                    labeledField("地址 1", text: $identityDraft.address1, contentType: .streetAddressLine1)
                    rowDivider
                    labeledField("地址 2", text: $identityDraft.address2, contentType: .streetAddressLine2)
                    rowDivider
                    labeledField("地址 3", text: $identityDraft.address3)
                    rowDivider
                    labeledField("城市", text: $identityDraft.city, contentType: .addressCity)
                    rowDivider
                    labeledField("省 / 州", text: $identityDraft.state, contentType: .addressState)
                    rowDivider
                    labeledField("邮政编码", text: $identityDraft.postalCode, contentType: .postalCode)
                    rowDivider
                    labeledField("国家或地区", text: $identityDraft.country, contentType: .countryName)
                }
            }

            groupTitle("证件")
            OpenVaultCard(padding: 0) {
                VStack(spacing: 0) {
                    secretField("社会安全号码", text: $identityDraft.ssn, isRevealed: $revealSSN)
                    rowDivider
                    secretField("护照号码", text: $identityDraft.passportNumber,
                                isRevealed: $revealPassportNumber)
                    rowDivider
                    secretField("证件号码", text: $identityDraft.licenseNumber,
                                isRevealed: $revealLicenseNumber)
                }
            }
        }
    }

    private var sshKeyFields: some View {
        Group {
            groupTitle("SSH 密钥")
            OpenVaultCard(padding: 0) {
                VStack(spacing: 0) {
                    secretField("私钥", text: $sshKeyDraft.privateKey,
                                isRevealed: $revealPrivateKey, multiline: true)
                    rowDivider
                    labeledField("公钥", text: $sshKeyDraft.publicKey,
                                 capitalization: .never, multiline: true)
                    rowDivider
                    labeledField("指纹", text: $sshKeyDraft.keyFingerprint,
                                 capitalization: .never)
                }
            }
        }
    }

    private var rowDivider: some View {
        Divider().padding(.leading, Spacing.lg)
    }

    private func groupTitle(_ title: String) -> some View {
        Text(title)
            .font(.subheadline)
            .foregroundStyle(Palette.secondaryText)
            .padding(.horizontal, Spacing.lg)
            .padding(.top, Spacing.sm)
    }

    private func labeledField(_ label: String, text: Binding<String>,
                              contentType: UITextContentType? = nil,
                              capitalization: TextInputAutocapitalization = .words,
                              keyboard: UIKeyboardType = .default,
                              multiline: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: Spacing.xxs) {
            Text(label).font(Typography.fieldLabel).foregroundStyle(Palette.secondaryText)
            TextField(label, text: text, axis: multiline ? .vertical : .horizontal)
                .lineLimit(multiline ? 2...8 : 1...1)
                .textContentType(contentType)
                .keyboardType(keyboard)
                .textInputAutocapitalization(capitalization)
                .autocorrectionDisabled()
        }
        .padding(.horizontal, Spacing.lg)
        .padding(.vertical, Spacing.sm)
        .frame(minHeight: multiline ? 84 : 66)
    }

    private func compactField(_ label: String, text: Binding<String>, keyboard: UIKeyboardType) -> some View {
        VStack(alignment: .leading, spacing: Spacing.xxs) {
            Text(label).font(Typography.fieldLabel).foregroundStyle(Palette.secondaryText)
            TextField(label, text: text).keyboardType(keyboard)
        }
        .frame(maxWidth: .infinity)
    }

    private func secretField(_ label: String, text: Binding<String>, isRevealed: Binding<Bool>,
                             contentType: UITextContentType? = nil,
                             keyboard: UIKeyboardType = .default,
                             multiline: Bool = false,
                             trailingAction: (() -> Void)? = nil) -> some View {
        VStack(alignment: .leading, spacing: Spacing.xxs) {
            Text(label).font(Typography.fieldLabel).foregroundStyle(Palette.secondaryText)
            HStack(alignment: multiline ? .top : .center, spacing: Spacing.sm) {
                Group {
                    if isRevealed.wrappedValue {
                        TextField(label, text: text, axis: multiline ? .vertical : .horizontal)
                            .lineLimit(multiline ? 3...10 : 1...1)
                    } else {
                        SecureField(label, text: text)
                    }
                }
                .font(Typography.secretValue)
                .textContentType(contentType)
                .keyboardType(keyboard)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .privacySensitive()

                if let trailingAction {
                    Button(action: trailingAction) { Image(systemName: "sparkles") }
                        .accessibilityLabel("生成\(label)")
                }
                Button { isRevealed.wrappedValue.toggle() } label: {
                    Image(systemName: isRevealed.wrappedValue ? "eye.slash" : "eye")
                }
                .accessibilityLabel(isRevealed.wrappedValue ? "隐藏\(label)" : "显示\(label)")
            }
            .buttonStyle(.plain)
            .foregroundStyle(Palette.accent)
        }
        .padding(.leading, Spacing.lg)
        .padding(.trailing, Spacing.sm)
        .padding(.vertical, Spacing.sm)
        .frame(minHeight: multiline ? 100 : 68)
    }

    private var existingFieldsDescription: String {
        guard let existing, !existing.fields.isEmpty else { return "" }
        return "此条目的 \(existing.fields.count) 个自定义字段会原样保留。"
    }

    private func save() {
        guard canSave else { return }
        isSaving = true
        errorMessage = nil
        let cipher = buildCipher()
        Task {
            do {
                let id: String
                if let existingID = existing?.id {
                    try await vault.updateCipher(id: existingID, cipher)
                    id = existingID
                } else {
                    id = try await vault.createCipher(cipher)
                }
                onSaved(id)
                dismiss()
            } catch {
                errorMessage = "无法存储条目，请稍后再试。"
            }
            isSaving = false
        }
    }

    private func buildCipher() -> PlaintextCipher {
        let login = selectedType == .login
            ? loginDraft.value(preserving: existing?.login)
            : existing?.login
        let card = selectedType == .card ? cardDraft.value : existing?.card
        let identity = selectedType == .identity ? identityDraft.value : existing?.identity
        let secureNote = selectedType == .secureNote
            ? (existing?.secureNote ?? PlaintextCipher.SecureNote())
            : existing?.secureNote
        let sshKey = selectedType == .sshKey ? sshKeyDraft.value : existing?.sshKey

        return PlaintextCipher(
            id: existing?.id,
            type: type,
            name: name.trimmingCharacters(in: .whitespacesAndNewlines),
            notes: notes.nilIfEmpty,
            folderID: existing?.folderID,
            organizationID: existing?.organizationID,
            protectedCipherKey: existing?.protectedCipherKey,
            favorite: favorite,
            reprompt: existing?.reprompt ?? 0,
            login: login,
            card: card,
            identity: identity,
            secureNote: secureNote,
            sshKey: sshKey,
            fields: existing?.fields ?? []
        )
    }
}

private struct LoginDraft {
    var username: String
    var password: String
    var totp: String
    var uris: [PlaintextCipher.Uri]

    init(_ login: PlaintextCipher.Login?) {
        username = login?.username ?? ""
        password = login?.password ?? ""
        totp = login?.totp ?? ""
        uris = login?.uris ?? []
        if uris.isEmpty { uris = [.init(uri: "")] }
    }

    func value(preserving existing: PlaintextCipher.Login?) -> PlaintextCipher.Login {
        let passwordValue = password.nilIfEmpty
        let passwordRevisionDate: Date?
        if passwordValue == existing?.password {
            passwordRevisionDate = existing?.passwordRevisionDate
        } else {
            passwordRevisionDate = passwordValue == nil ? nil : Date()
        }
        return PlaintextCipher.Login(
            username: username.nilIfEmpty,
            password: passwordValue,
            totp: totp.nilIfEmpty,
            uris: uris.filter { $0.uri.nilIfEmpty != nil },
            fido2Credentials: existing?.fido2Credentials ?? [],
            passwordRevisionDate: passwordRevisionDate
        )
    }
}

private struct CardDraft {
    var cardholderName: String
    var brand: String
    var number: String
    var expMonth: String
    var expYear: String
    var code: String

    init(_ card: PlaintextCipher.Card?) {
        cardholderName = card?.cardholderName ?? ""
        brand = card?.brand ?? ""
        number = card?.number ?? ""
        expMonth = card?.expMonth ?? ""
        expYear = card?.expYear ?? ""
        code = card?.code ?? ""
    }

    var value: PlaintextCipher.Card {
        .init(cardholderName: cardholderName.nilIfEmpty, brand: brand.nilIfEmpty,
              number: number.nilIfEmpty, expMonth: expMonth.nilIfEmpty,
              expYear: expYear.nilIfEmpty, code: code.nilIfEmpty)
    }
}

private struct IdentityDraft {
    var title = ""
    var firstName = ""
    var middleName = ""
    var lastName = ""
    var address1 = ""
    var address2 = ""
    var address3 = ""
    var city = ""
    var state = ""
    var postalCode = ""
    var country = ""
    var company = ""
    var email = ""
    var phone = ""
    var ssn = ""
    var username = ""
    var passportNumber = ""
    var licenseNumber = ""

    init(_ value: PlaintextCipher.Identity?) {
        title = value?.title ?? ""; firstName = value?.firstName ?? ""
        middleName = value?.middleName ?? ""; lastName = value?.lastName ?? ""
        address1 = value?.address1 ?? ""; address2 = value?.address2 ?? ""
        address3 = value?.address3 ?? ""; city = value?.city ?? ""
        state = value?.state ?? ""; postalCode = value?.postalCode ?? ""
        country = value?.country ?? ""; company = value?.company ?? ""
        email = value?.email ?? ""; phone = value?.phone ?? ""
        ssn = value?.ssn ?? ""; username = value?.username ?? ""
        passportNumber = value?.passportNumber ?? ""
        licenseNumber = value?.licenseNumber ?? ""
    }

    var value: PlaintextCipher.Identity {
        .init(title: title.nilIfEmpty, firstName: firstName.nilIfEmpty,
              middleName: middleName.nilIfEmpty, lastName: lastName.nilIfEmpty,
              address1: address1.nilIfEmpty, address2: address2.nilIfEmpty,
              address3: address3.nilIfEmpty, city: city.nilIfEmpty,
              state: state.nilIfEmpty, postalCode: postalCode.nilIfEmpty,
              country: country.nilIfEmpty, company: company.nilIfEmpty,
              email: email.nilIfEmpty, phone: phone.nilIfEmpty, ssn: ssn.nilIfEmpty,
              username: username.nilIfEmpty, passportNumber: passportNumber.nilIfEmpty,
              licenseNumber: licenseNumber.nilIfEmpty)
    }
}

private struct SshKeyDraft {
    var privateKey: String
    var publicKey: String
    var keyFingerprint: String

    init(_ value: PlaintextCipher.SshKey?) {
        privateKey = value?.privateKey ?? ""
        publicKey = value?.publicKey ?? ""
        keyFingerprint = value?.keyFingerprint ?? ""
    }

    var value: PlaintextCipher.SshKey {
        .init(privateKey: privateKey.nilIfEmpty, publicKey: publicKey.nilIfEmpty,
              keyFingerprint: keyFingerprint.nilIfEmpty)
    }
}

private extension String {
    var nilIfEmpty: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : self
    }
}
