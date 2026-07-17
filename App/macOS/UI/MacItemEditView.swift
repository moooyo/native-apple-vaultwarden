import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels

@available(macOS 27.0, *)
struct MacItemEditView: View {
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

    init(vault: VaultService, existing: PlaintextCipher? = nil,
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
        guard name.nilIfBlank != nil, !isSaving else { return false }
        if case .unknown = selectedType { return false }
        return true
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(.white.opacity(0.08))

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    sectionTitle("基本信息")
                    card {
                        VStack(spacing: 0) {
                            editRow("类型") {
                                Picker("类型", selection: $type) {
                                    Text("登录").tag(CipherType.login.rawValue)
                                    Text("安全笔记").tag(CipherType.secureNote.rawValue)
                                    Text("银行卡").tag(CipherType.card.rawValue)
                                    Text("身份").tag(CipherType.identity.rawValue)
                                    Text("SSH 密钥").tag(CipherType.sshKey.rawValue)
                                }
                                .labelsHidden()
                                .frame(width: 140)
                                .disabled(existing != nil)
                            }
                            rowDivider
                            editTextField("名称", text: $name, prompt: "条目名称")
                            rowDivider
                            editRow("置顶") { Toggle("", isOn: $favorite).labelsHidden() }
                        }
                    }

                    if existing != nil {
                        Text("已有条目的类型不可更改；保存时会保留未显示的自定义字段、passkey 与其他网址。")
                            .font(.system(size: 11.5))
                            .foregroundStyle(.white.opacity(0.42))
                            .padding(.horizontal, 4)
                    }

                    typeSpecificFields

                    sectionTitle("备注")
                    card {
                        TextField("添加备注…", text: $notes, axis: .vertical)
                            .textFieldStyle(.plain)
                            .font(.system(size: 13.5))
                            .lineLimit(4...10)
                            .padding(15)
                    }

                    if let errorMessage {
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                            .font(.system(size: 12.5))
                            .foregroundStyle(Color.orange)
                    }
                }
                .padding(20)
            }
        }
        .frame(width: 580, height: 720)
        .background(MacOpenVaultStyle.detail)
    }

    @ViewBuilder
    private var typeSpecificFields: some View {
        switch selectedType {
        case .login:
            sectionTitle("登录凭据")
            card {
                VStack(spacing: 0) {
                    editTextField("用户名", text: $loginDraft.username, prompt: "用户名或邮箱")
                    rowDivider
                    secretField("密码", text: $loginDraft.password, reveal: $revealPassword)
                    rowDivider
                    secretField("验证器密钥", text: $loginDraft.totp, reveal: $revealTOTP,
                                prompt: "Base32 或 otpauth://")
                }
            }
            sectionTitle("网站")
            card { editTextField("网址", text: $loginDraft.uri, prompt: "https://example.com") }

        case .secureNote:
            EmptyView()

        case .card:
            sectionTitle("银行卡")
            card {
                VStack(spacing: 0) {
                    editTextField("持卡人", text: $cardDraft.cardholderName, prompt: "持卡人姓名")
                    rowDivider
                    editTextField("品牌", text: $cardDraft.brand, prompt: "Visa、Mastercard…")
                    rowDivider
                    secretField("卡号", text: $cardDraft.number, reveal: $revealCardNumber)
                    rowDivider
                    HStack(spacing: 12) {
                        compactTextField("月份", text: $cardDraft.expMonth)
                        compactTextField("年份", text: $cardDraft.expYear)
                    }
                    .padding(.horizontal, 15)
                    .frame(minHeight: 54)
                    rowDivider
                    secretField("安全码（CVV）", text: $cardDraft.code, reveal: $revealCardCode)
                }
            }

        case .identity:
            sectionTitle("姓名")
            card {
                VStack(spacing: 0) {
                    editTextField("称谓", text: $identityDraft.title, prompt: "称谓")
                    rowDivider
                    editTextField("名字", text: $identityDraft.firstName, prompt: "名字")
                    rowDivider
                    editTextField("中间名", text: $identityDraft.middleName, prompt: "中间名")
                    rowDivider
                    editTextField("姓氏", text: $identityDraft.lastName, prompt: "姓氏")
                }
            }
            sectionTitle("联系信息")
            card {
                VStack(spacing: 0) {
                    editTextField("用户名", text: $identityDraft.username, prompt: "用户名")
                    rowDivider
                    editTextField("公司", text: $identityDraft.company, prompt: "公司")
                    rowDivider
                    editTextField("邮箱", text: $identityDraft.email, prompt: "邮箱")
                    rowDivider
                    editTextField("电话", text: $identityDraft.phone, prompt: "电话")
                }
            }
            sectionTitle("地址")
            card {
                VStack(spacing: 0) {
                    editTextField("地址 1", text: $identityDraft.address1, prompt: "街道地址")
                    rowDivider
                    editTextField("地址 2", text: $identityDraft.address2, prompt: "公寓、楼层")
                    rowDivider
                    editTextField("地址 3", text: $identityDraft.address3, prompt: "其他地址")
                    rowDivider
                    editTextField("城市", text: $identityDraft.city, prompt: "城市")
                    rowDivider
                    editTextField("省/州", text: $identityDraft.state, prompt: "省或州")
                    rowDivider
                    editTextField("邮编", text: $identityDraft.postalCode, prompt: "邮政编码")
                    rowDivider
                    editTextField("国家/地区", text: $identityDraft.country, prompt: "国家或地区")
                }
            }
            sectionTitle("证件")
            card {
                VStack(spacing: 0) {
                    secretField("社会安全号", text: $identityDraft.ssn, reveal: $revealSSN)
                    rowDivider
                    secretField("护照号码", text: $identityDraft.passportNumber,
                                reveal: $revealPassportNumber)
                    rowDivider
                    secretField("驾照号码", text: $identityDraft.licenseNumber,
                                reveal: $revealLicenseNumber)
                }
            }

        case .sshKey:
            sectionTitle("SSH 密钥")
            card {
                VStack(spacing: 0) {
                    secretField("私钥", text: $sshKeyDraft.privateKey, reveal: $revealPrivateKey,
                                multiline: true)
                    rowDivider
                    editTextField("公钥", text: $sshKeyDraft.publicKey, prompt: "公钥", multiline: true)
                    rowDivider
                    editTextField("指纹", text: $sshKeyDraft.keyFingerprint, prompt: "密钥指纹")
                }
            }

        case .unknown:
            ContentUnavailableView("无法编辑此类型", systemImage: "questionmark.square.dashed",
                                   description: Text("服务器返回了当前版本尚不认识的条目类型。"))
        }
    }

    private var header: some View {
        HStack {
            Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
            Spacer()
            Text(existing == nil ? "新建条目" : "编辑条目")
                .font(.system(size: 15, weight: .semibold))
            Spacer()
            Button(action: save) {
                if isSaving { ProgressView().controlSize(.small) } else { Text("存储") }
            }
            .buttonStyle(.glassProminent)
            .keyboardShortcut(.defaultAction)
            .disabled(!canSave)
        }
        .padding(.horizontal, 18)
        .frame(height: 52)
    }

    private func sectionTitle(_ title: String) -> some View {
        Text(title)
            .font(.system(size: 11.5, weight: .semibold))
            .foregroundStyle(.white.opacity(0.42))
            .padding(.horizontal, 4)
            .padding(.bottom, -8)
    }

    private func card<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 0, content: content)
            .overlay {
                RoundedRectangle(cornerRadius: CornerRadius.macCard, style: .continuous)
                    .stroke(.white.opacity(0.07), lineWidth: 0.5)
            }
    }

    private func editRow<Accessory: View>(_ label: String,
                                          @ViewBuilder accessory: () -> Accessory) -> some View {
        HStack {
            Text(label).font(.system(size: 13.5))
            Spacer()
            accessory()
        }
        .padding(.horizontal, 15)
        .frame(minHeight: 50)
    }

    private func editTextField(_ label: String, text: Binding<String>, prompt: String,
                               multiline: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).fieldLabel()
            TextField(prompt, text: text, axis: multiline ? .vertical : .horizontal)
                .textFieldStyle(.plain)
                .font(.system(size: 13.5, design: multiline ? .monospaced : .default))
                .lineLimit(multiline ? 2...8 : 1...1)
        }
        .padding(.horizontal, 15)
        .frame(minHeight: multiline ? 78 : 54)
    }

    private func compactTextField(_ label: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).fieldLabel()
            TextField(label, text: text).textFieldStyle(.plain)
        }
        .frame(maxWidth: .infinity)
    }

    private func secretField(_ label: String, text: Binding<String>, reveal: Binding<Bool>,
                             prompt: String? = nil, multiline: Bool = false) -> some View {
        HStack(alignment: multiline ? .top : .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(label).fieldLabel()
                Group {
                    if reveal.wrappedValue {
                        TextField(prompt ?? label, text: text, axis: multiline ? .vertical : .horizontal)
                            .lineLimit(multiline ? 3...10 : 1...1)
                    } else {
                        SecureField(prompt ?? label, text: text)
                    }
                }
                .font(.system(size: 13.5, design: .monospaced))
                .textFieldStyle(.plain)
                .privacySensitive()
            }
            Spacer()
            Button { reveal.wrappedValue.toggle() } label: {
                Image(systemName: reveal.wrappedValue ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel(reveal.wrappedValue ? "隐藏\(label)" : "显示\(label)")
        }
        .padding(.horizontal, 15)
        .frame(minHeight: multiline ? 96 : 54)
    }

    private var rowDivider: some View {
        Divider().overlay(.white.opacity(0.08)).padding(.leading, 15)
    }

    private func save() {
        guard canSave else { return }
        isSaving = true
        errorMessage = nil
        let cipher = buildCipher()
        Task {
            do {
                if let id = existing?.id {
                    try await vault.updateCipher(id: id, cipher)
                    onSaved(id)
                } else {
                    onSaved(try await vault.createCipher(cipher))
                }
                dismiss()
            } catch {
                errorMessage = "无法存储条目，请重试。"
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
            notes: notes.nilIfBlank,
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
    var uri: String

    init(_ login: PlaintextCipher.Login?) {
        username = login?.username ?? ""
        password = login?.password ?? ""
        totp = login?.totp ?? ""
        uri = login?.uris.first?.uri ?? ""
    }

    func value(preserving existing: PlaintextCipher.Login?) -> PlaintextCipher.Login {
        var uris = existing?.uris ?? []
        if let primaryURI = uri.nilIfBlank {
            if uris.isEmpty { uris.append(PlaintextCipher.Uri(uri: primaryURI)) }
            else { uris[0].uri = primaryURI }
        } else if !uris.isEmpty {
            uris.removeFirst()
        }
        let passwordValue = password.nilIfBlank
        let passwordRevisionDate = passwordValue == existing?.password
            ? existing?.passwordRevisionDate
            : (passwordValue == nil ? nil : Date())
        return PlaintextCipher.Login(
            username: username.nilIfBlank,
            password: passwordValue,
            totp: totp.nilIfBlank,
            uris: uris,
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
        PlaintextCipher.Card(cardholderName: cardholderName.nilIfBlank,
                             brand: brand.nilIfBlank,
                             number: number.nilIfBlank,
                             expMonth: expMonth.nilIfBlank,
                             expYear: expYear.nilIfBlank,
                             code: code.nilIfBlank)
    }
}

private struct IdentityDraft {
    var title: String
    var firstName: String
    var middleName: String
    var lastName: String
    var address1: String
    var address2: String
    var address3: String
    var city: String
    var state: String
    var postalCode: String
    var country: String
    var company: String
    var email: String
    var phone: String
    var ssn: String
    var username: String
    var passportNumber: String
    var licenseNumber: String

    init(_ value: PlaintextCipher.Identity?) {
        title = value?.title ?? ""; firstName = value?.firstName ?? ""
        middleName = value?.middleName ?? ""; lastName = value?.lastName ?? ""
        address1 = value?.address1 ?? ""; address2 = value?.address2 ?? ""
        address3 = value?.address3 ?? ""; city = value?.city ?? ""
        state = value?.state ?? ""; postalCode = value?.postalCode ?? ""
        country = value?.country ?? ""; company = value?.company ?? ""
        email = value?.email ?? ""; phone = value?.phone ?? ""
        ssn = value?.ssn ?? ""; username = value?.username ?? ""
        passportNumber = value?.passportNumber ?? ""; licenseNumber = value?.licenseNumber ?? ""
    }

    var value: PlaintextCipher.Identity {
        PlaintextCipher.Identity(
            title: title.nilIfBlank, firstName: firstName.nilIfBlank,
            middleName: middleName.nilIfBlank, lastName: lastName.nilIfBlank,
            address1: address1.nilIfBlank, address2: address2.nilIfBlank,
            address3: address3.nilIfBlank, city: city.nilIfBlank,
            state: state.nilIfBlank, postalCode: postalCode.nilIfBlank,
            country: country.nilIfBlank, company: company.nilIfBlank,
            email: email.nilIfBlank, phone: phone.nilIfBlank,
            ssn: ssn.nilIfBlank, username: username.nilIfBlank,
            passportNumber: passportNumber.nilIfBlank,
            licenseNumber: licenseNumber.nilIfBlank
        )
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
        PlaintextCipher.SshKey(privateKey: privateKey.nilIfBlank,
                               publicKey: publicKey.nilIfBlank,
                               keyFingerprint: keyFingerprint.nilIfBlank)
    }
}

@available(macOS 27.0, *)
private extension View {
    func fieldLabel() -> some View {
        font(.system(size: 11)).foregroundStyle(.white.opacity(0.45))
    }
}
