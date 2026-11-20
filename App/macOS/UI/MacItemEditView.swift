import SwiftUI
import UIShared
import VaultRepository
import VaultModels

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
        NavigationStack {
            Form {
                Section {
                    Picker("类型", selection: $type) {
                        Text("登录").tag(CipherType.login.rawValue)
                        Text("安全笔记").tag(CipherType.secureNote.rawValue)
                        Text("银行卡").tag(CipherType.card.rawValue)
                        Text("身份").tag(CipherType.identity.rawValue)
                        Text("SSH 密钥").tag(CipherType.sshKey.rawValue)
                    }
                    .disabled(existing != nil)
                    TextField("名称", text: $name, prompt: Text("条目名称"))
                    Toggle("置顶", isOn: $favorite)
                } header: {
                    Text("基本信息")
                } footer: {
                    if existing != nil {
                        Text("已有条目的类型不可更改；保存时会保留未显示的自定义字段、passkey 与其他网址。")
                    }
                }

                typeSpecificFields

                Section("备注") {
                    TextField("备注", text: $notes, prompt: Text("添加备注…"), axis: .vertical)
                        .labelsHidden()
                        .lineLimit(4...10)
                        .privacySensitive()
                }
            }
            .formStyle(.grouped)
            .navigationTitle(existing == nil ? "新建条目" : "编辑条目")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                }

                ToolbarItem(placement: .confirmationAction) {
                    Button(action: save) {
                        if isSaving {
                            ProgressView().controlSize(.small).accessibilityLabel("正在存储")
                        } else {
                            Text("存储")
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSave)
                }
            }
        }
        .frame(minWidth: 380, idealWidth: 540, minHeight: 320, idealHeight: 560)
        .presentationSizing(.form)
        .alert("存储失败", isPresented: Binding(
            get: { errorMessage != nil },
            set: { if !$0 { errorMessage = nil } }
        )) {
            Button("好", role: .cancel) {}
        } message: {
            Text(errorMessage ?? "")
        }
    }

    @ViewBuilder
    private var typeSpecificFields: some View {
        switch selectedType {
        case .login:
            Section("登录凭据") {
                TextField("用户名", text: $loginDraft.username, prompt: Text("用户名或邮箱"))
                secretField("密码", text: $loginDraft.password, reveal: $revealPassword)
                secretField("验证器密钥", text: $loginDraft.totp, reveal: $revealTOTP,
                            prompt: "Base32 或 otpauth://")
            }
            Section("网站") {
                TextField("网址", text: $loginDraft.uri, prompt: Text("https://example.com"))
            }

        case .secureNote:
            EmptyView()

        case .card:
            Section("银行卡") {
                TextField("持卡人", text: $cardDraft.cardholderName, prompt: Text("持卡人姓名"))
                TextField("品牌", text: $cardDraft.brand, prompt: Text("Visa、Mastercard…"))
                secretField("卡号", text: $cardDraft.number, reveal: $revealCardNumber)
                TextField("到期月份", text: $cardDraft.expMonth)
                TextField("到期年份", text: $cardDraft.expYear)
                secretField("安全码（CVV）", text: $cardDraft.code, reveal: $revealCardCode)
            }

        case .identity:
            Section("姓名") {
                TextField("称谓", text: $identityDraft.title)
                TextField("名字", text: $identityDraft.firstName)
                TextField("中间名", text: $identityDraft.middleName)
                TextField("姓氏", text: $identityDraft.lastName)
            }
            Section("联系信息") {
                TextField("用户名", text: $identityDraft.username)
                TextField("公司", text: $identityDraft.company)
                TextField("邮箱", text: $identityDraft.email)
                TextField("电话", text: $identityDraft.phone)
            }
            Section("地址") {
                TextField("地址 1", text: $identityDraft.address1, prompt: Text("街道地址"))
                TextField("地址 2", text: $identityDraft.address2, prompt: Text("公寓、楼层"))
                TextField("地址 3", text: $identityDraft.address3, prompt: Text("其他地址"))
                TextField("城市", text: $identityDraft.city)
                TextField("省/州", text: $identityDraft.state, prompt: Text("省或州"))
                TextField("邮编", text: $identityDraft.postalCode, prompt: Text("邮政编码"))
                TextField("国家/地区", text: $identityDraft.country)
            }
            Section("证件") {
                secretField("社会安全号", text: $identityDraft.ssn, reveal: $revealSSN)
                secretField("护照号码", text: $identityDraft.passportNumber, reveal: $revealPassportNumber)
                secretField("驾照号码", text: $identityDraft.licenseNumber, reveal: $revealLicenseNumber)
            }

        case .sshKey:
            Section("SSH 密钥") {
                secretField("私钥", text: $sshKeyDraft.privateKey, reveal: $revealPrivateKey, multiline: true)
                TextField("公钥", text: $sshKeyDraft.publicKey, axis: .vertical)
                    .font(.body.monospaced())
                    .lineLimit(2...8)
                TextField("指纹", text: $sshKeyDraft.keyFingerprint, prompt: Text("密钥指纹"))
            }

        case .unknown:
            ContentUnavailableView("无法编辑此类型", systemImage: "questionmark.square.dashed",
                                   description: Text("服务器返回了当前版本尚不认识的条目类型。"))
        }
    }

    private func secretField(_ label: String, text: Binding<String>, reveal: Binding<Bool>,
                             prompt: String? = nil, multiline: Bool = false) -> some View {
        let action = reveal.wrappedValue ? "隐藏\(label)" : "显示\(label)"
        return LabeledContent(label) {
            HStack {
                Group {
                    if reveal.wrappedValue {
                        TextField(label, text: text, prompt: Text(prompt ?? label),
                                  axis: multiline ? .vertical : .horizontal)
                            .lineLimit(multiline ? 3...10 : 1...1)
                    } else {
                        SecureField(label, text: text, prompt: Text(prompt ?? label))
                    }
                }
                .labelsHidden()
                .font(.body.monospaced())
                .privacySensitive()

                Button(action, systemImage: reveal.wrappedValue ? "eye.slash" : "eye") {
                    reveal.wrappedValue.toggle()
                }
                .labelStyle(.iconOnly)
                .buttonStyle(.borderless)
                .help(action)
            }
        }
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
