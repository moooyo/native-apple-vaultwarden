import SwiftUI
import UIShared
import VaultRepository
import VaultModels
import DesignSystem
import Generators

struct MacItemEditView: View {
    private let vault: VaultService
    @State private var existing: PlaintextCipher?
    private let onSaved: (String) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var type: Int
    @State private var name: String
    @State private var folderID: String?
    @State private var folders: [PlaintextFolder] = []
    @State private var folderLoadFailed = false
    @State private var creatingFolder = false
    @State private var folderName = ""
    @FocusState private var nameFocused: Bool
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

    init(vault: VaultService, existing: PlaintextCipher? = nil, initialType: CipherType = .login,
         initialFolderID: String? = nil,
         onSaved: @escaping (String) -> Void) {
        self.vault = vault
        _existing = State(initialValue: existing)
        self.onSaved = onSaved
        _type = State(initialValue: existing?.type ?? initialType.rawValue)
        _name = State(initialValue: existing?.name ?? "")
        _folderID = State(initialValue: existing == nil ? initialFolderID : existing?.folderID)
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
            HStack {
                Text(existing == nil ? "新建条目" : "编辑条目").font(.title2.bold()).accessibilityAddTraits(.isHeader)
                Spacer()
                Picker("类型", selection: $type) {
                    Text("登录").tag(CipherType.login.rawValue)
                    Text("银行卡").tag(CipherType.card.rawValue)
                    Text("身份").tag(CipherType.identity.rawValue)
                    Text("安全笔记").tag(CipherType.secureNote.rawValue)
                    Text("SSH 密钥").tag(CipherType.sshKey.rawValue)
                }.fixedSize().disabled(existing != nil)
            }.padding(.horizontal, 22).padding(.top, 20)

            Form {
                Section {
                    TextField("名称", text: $name, prompt: Text("必填")).focused($nameFocused)
                    folderPicker
                }

                typeSpecificFields

                Section {
                    Toggle("置顶", isOn: $favorite).toggleStyle(.checkbox)
                    TextField(selectedType == .secureNote ? "内容" : "备注", text: $notes, prompt: Text("选填"), axis: .vertical)
                        .lineLimit(4...10)
                        .privacySensitive()
                }
            }
            .formStyle(.grouped)
            .disabled(isSaving)
            HStack(spacing: 10) {
                Spacer()
                if isSaving { ProgressView().controlSize(.small).accessibilityLabel("正在存储") }
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction).disabled(isSaving)
                Button("存储", action: save).keyboardShortcut(.defaultAction).disabled(!canSave)
            }.padding(.horizontal, 22).padding(.bottom, 18)
        }
        .frame(width: 600, height: 580)
        .interactiveDismissDisabled(isSaving)
        .task {
            nameFocused = true
            await loadFolders()
        }
        .alert("新建文件夹", isPresented: $creatingFolder) {
            TextField("文件夹名称", text: $folderName)
            Button("取消", role: .cancel) {}
            Button("新建") {
                guard let proposed = folderName.nilIfBlank else { return }
                isSaving = true
                Task {
                    defer { isSaving = false }
                    do {
                        folderID = try await vault.createFolder(name: proposed.trimmingCharacters(in: .whitespacesAndNewlines))
                        await loadFolders()
                    } catch {
                        errorMessage = "无法新建文件夹，请重试。"
                    }
                }
            }.disabled(folderName.nilIfBlank == nil)
        }
        .alert("操作未完成", isPresented: Binding(
            get: { errorMessage != nil },
            set: { if !$0 { errorMessage = nil } }
        )) {
            Button("好", role: .cancel) {}
        } message: {
            Text(errorMessage ?? "")
        }
    }

    private var folderPicker: some View {
        LabeledContent("文件夹") {
            Menu {
                Picker("文件夹", selection: $folderID) {
                    Text("无文件夹").tag(String?.none)
                    ForEach(folders, id: \.id) { folder in Text(folder.name).tag(Optional(folder.id)) }
                    if let folderID, !folders.contains(where: { $0.id == folderID }) { Text("当前文件夹").tag(Optional(folderID)) }
                }
                .pickerStyle(.inline)
                Divider()
                if folderLoadFailed { Button("重新载入文件夹") { Task { await loadFolders() } } }
                Button("新建文件夹…") { folderName = ""; creatingFolder = true }
            } label: {
                Text(folders.first(where: { $0.id == folderID })?.name ?? (folderID == nil ? "无文件夹" : "当前文件夹"))
            }.fixedSize()
        }
    }

    private func loadFolders() async {
        do { folders = try await vault.folders(); folderLoadFailed = false }
        catch { folderLoadFailed = true }
    }

    @ViewBuilder
    private var typeSpecificFields: some View {
        switch selectedType {
        case .login:
            Section("登录凭据") {
                TextField("用户名", text: $loginDraft.username, prompt: Text("用户名或邮箱"))
                HStack(spacing: 10) {
                    secretField("密码", text: $loginDraft.password, reveal: $revealPassword)
                    Button("生成", systemImage: "wand.and.stars") {
                        do {
                            loginDraft.password = try PasswordGenerator.generate(.init(length: 20, useSpecial: true))
                        } catch { errorMessage = "无法生成密码，请重试。" }
                    }.help("生成新密码")
                }
                if !loginDraft.password.isEmpty {
                    SecretStrengthMeter(strength: .estimate(loginDraft.password))
                }
                secretField("验证器密钥", text: $loginDraft.totp, reveal: $revealTOTP,
                            prompt: "Base32 或 otpauth://")
            }
            Section("网站") {
                ForEach($loginDraft.uris) { $entry in
                    HStack {
                        TextField("网址", text: $entry.uri, prompt: Text("https://"))
                        Button("移除网址", systemImage: "minus.circle") {
                            loginDraft.uris.removeAll { $0.id == entry.id }
                        }.labelStyle(.iconOnly).buttonStyle(.borderless).help("移除网址")
                    }
                }
                Button("添加网站", systemImage: "plus") { loginDraft.uris.append(WebsiteDraft(uri: "")) }
                    .buttonStyle(.borderless)
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
        Task {
            do {
                if let id = existing?.id {
                    let current = try await vault.cipher(id: id)
                    guard current == existing else {
                        errorMessage = "条目已更改，请关闭此表单后重新编辑。"
                        isSaving = false
                        return
                    }
                    try await vault.updateCipher(id: id, buildCipher(preserving: current))
                    onSaved(id)
                } else {
                    onSaved(try await vault.createCipher(buildCipher(preserving: nil)))
                }
                dismiss()
            } catch {
                errorMessage = "无法存储条目，请重试。"
            }
            isSaving = false
        }
    }

    private func buildCipher(preserving existing: PlaintextCipher?) -> PlaintextCipher {
        var result = existing ?? PlaintextCipher(type: type, name: "")
        result.name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        result.notes = notes.isEmpty ? nil : notes
        result.folderID = folderID
        result.favorite = favorite
        switch selectedType {
        case .login: result.login = loginDraft.value(preserving: existing?.login)
        case .card: result.card = cardDraft.value
        case .identity: result.identity = identityDraft.value
        case .secureNote: result.secureNote = existing?.secureNote ?? .init()
        case .sshKey: result.sshKey = sshKeyDraft.value
        case .unknown: break
        }
        return result
    }
}

private struct LoginDraft {
    var username: String
    var password: String
    var totp: String
    var uris: [WebsiteDraft]

    init(_ login: PlaintextCipher.Login?) {
        username = login?.username ?? ""
        password = login?.password ?? ""
        totp = login?.totp ?? ""
        let existing = login?.uris ?? []
        uris = existing.isEmpty ? [WebsiteDraft(uri: "")] : existing.map { WebsiteDraft(uri: $0.uri, match: $0.match) }
    }

    func value(preserving existing: PlaintextCipher.Login?) -> PlaintextCipher.Login {
        let passwordValue = password.isEmpty ? nil : password
        let passwordRevisionDate = passwordValue == existing?.password
            ? existing?.passwordRevisionDate
            : (passwordValue == nil ? nil : Date())
        var result = existing ?? PlaintextCipher.Login()
        result.username = username.isEmpty ? nil : username
        result.password = passwordValue
        result.totp = totp.nilIfBlank
        result.uris = uris.compactMap { entry in entry.uri.nilIfBlank.map { PlaintextCipher.Uri(uri: $0, match: entry.match) } }
        result.passwordRevisionDate = passwordRevisionDate
        return result
    }
}

private struct WebsiteDraft: Identifiable {
    let id = UUID()
    var uri: String
    var match: Int? = nil
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
