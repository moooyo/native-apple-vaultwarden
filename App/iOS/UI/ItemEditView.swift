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
    @State private var username: String
    @State private var password: String
    @State private var totp: String
    @State private var uris: [String]
    @State private var notes: String
    @State private var favorite: Bool
    @State private var revealPassword = false
    @State private var revealTOTP = false
    @State private var isSaving = false
    @State private var errorMessage: String?
    @State private var generator = GeneratorModel()

    public init(vault: VaultService, existing: PlaintextCipher? = nil,
                onSaved: @escaping (String) -> Void) {
        self.vault = vault
        self.existing = existing
        self.onSaved = onSaved
        _type = State(initialValue: existing?.type ?? CipherType.login.rawValue)
        _name = State(initialValue: existing?.name ?? "")
        _username = State(initialValue: existing?.login?.username ?? "")
        _password = State(initialValue: existing?.login?.password ?? "")
        _totp = State(initialValue: existing?.login?.totp ?? "")
        let values = existing?.login?.uris.map(\.uri).filter { !$0.isEmpty } ?? []
        _uris = State(initialValue: values.isEmpty ? [""] : values)
        _notes = State(initialValue: existing?.notes ?? "")
        _favorite = State(initialValue: existing?.favorite ?? false)
    }

    private var isLogin: Bool { type == CipherType.login.rawValue }
    private var canSave: Bool {
        !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !isSaving
    }

    public var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: Spacing.md) {
                typeCard

                groupTitle("基本信息")
                OpenVaultCard(padding: 0) {
                    VStack(spacing: 0) {
                        labeledField("名称", text: $name, contentType: .name)
                        Divider().padding(.leading, Spacing.lg)
                        Toggle(isOn: $favorite) {
                            Label("置顶", systemImage: "star")
                        }
                        .padding(.horizontal, Spacing.lg)
                        .frame(minHeight: 54)
                    }
                }

                if isLogin {
                    groupTitle("登录凭据")
                    credentialsCard

                    groupTitle("网站")
                    websitesCard
                }

                groupTitle("备注")
                OpenVaultCard {
                    TextField("添加备注…", text: $notes, axis: .vertical)
                        .lineLimit(4...10)
                        .frame(minHeight: 110, alignment: .top)
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
                    if existing?.type == CipherType.card.rawValue {
                        Text("银行卡").tag(CipherType.card.rawValue)
                    }
                    if existing?.type == CipherType.identity.rawValue {
                        Text("身份").tag(CipherType.identity.rawValue)
                    }
                    if existing?.type == CipherType.sshKey.rawValue {
                        Text("SSH 密钥").tag(CipherType.sshKey.rawValue)
                    }
                }
                .labelsHidden()
                .pickerStyle(.menu)
            }
        }
    }

    private var credentialsCard: some View {
        OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                labeledField("用户名", text: $username, contentType: .username,
                             capitalization: .never)
                Divider().padding(.leading, Spacing.lg)
                passwordField
                Divider().padding(.leading, Spacing.lg)
                totpSecretField
            }
        }
    }

    private var passwordField: some View {
        VStack(alignment: .leading, spacing: Spacing.xxs) {
            Text("密码")
                .font(Typography.fieldLabel)
                .foregroundStyle(Palette.secondaryText)
            HStack(spacing: Spacing.sm) {
                Group {
                    if revealPassword {
                        TextField("密码", text: $password)
                    } else {
                        SecureField("密码", text: $password)
                    }
                }
                .font(Typography.secretValue)
                .textContentType(.password)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()

                Button {
                    generator.regenerate()
                    password = generator.generated
                } label: {
                    Image(systemName: "sparkles")
                }
                .buttonStyle(.plain)
                .foregroundStyle(Palette.accent)
                .frame(width: 36, height: 44)
                .accessibilityLabel("生成密码")

                Button { revealPassword.toggle() } label: {
                    Image(systemName: revealPassword ? "eye.slash" : "eye")
                }
                .buttonStyle(.plain)
                .foregroundStyle(Palette.accent)
                .frame(width: 36, height: 44)
                .accessibilityLabel(revealPassword ? "隐藏密码" : "显示密码")
            }
        }
        .padding(.leading, Spacing.lg)
        .padding(.trailing, Spacing.sm)
        .padding(.vertical, Spacing.sm)
        .frame(minHeight: 68)
    }

    private var totpSecretField: some View {
        VStack(alignment: .leading, spacing: Spacing.xxs) {
            Text("验证器密钥")
                .font(Typography.fieldLabel)
                .foregroundStyle(Palette.secondaryText)
            HStack(spacing: Spacing.sm) {
                Group {
                    if revealTOTP {
                        TextField("设置验证码…", text: $totp)
                    } else {
                        SecureField("设置验证码…", text: $totp)
                    }
                }
                .font(Typography.secretValue)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .privacySensitive()

                Button { revealTOTP.toggle() } label: {
                    Image(systemName: revealTOTP ? "eye.slash" : "eye")
                }
                .buttonStyle(.plain)
                .foregroundStyle(Palette.accent)
                .frame(width: 36, height: 44)
                .accessibilityLabel(revealTOTP ? "隐藏验证器密钥" : "显示验证器密钥")
            }
        }
        .padding(.leading, Spacing.lg)
        .padding(.trailing, Spacing.sm)
        .padding(.vertical, Spacing.sm)
        .frame(minHeight: 68)
    }

    private var websitesCard: some View {
        OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                ForEach(uris.indices, id: \.self) { index in
                    HStack(spacing: Spacing.sm) {
                        VStack(alignment: .leading, spacing: Spacing.xxs) {
                            Text(index == 0 ? "网站" : "网站 \(index + 1)")
                                .font(Typography.fieldLabel)
                                .foregroundStyle(Palette.secondaryText)
                            TextField("https://example.com", text: $uris[index])
                                .textContentType(.URL)
                                .keyboardType(.URL)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                        }
                        if uris.count > 1 {
                            Button(role: .destructive) { uris.remove(at: index) } label: {
                                Image(systemName: "minus.circle.fill")
                            }
                            .buttonStyle(.plain)
                            .frame(width: 40, height: 44)
                            .accessibilityLabel("删除网站")
                        }
                    }
                    .padding(.horizontal, Spacing.lg)
                    .padding(.vertical, Spacing.sm)
                    .frame(minHeight: 66)

                    Divider().padding(.leading, Spacing.lg)
                }

                Button {
                    uris.append("")
                } label: {
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

    private func groupTitle(_ title: String) -> some View {
        Text(title)
            .font(.subheadline)
            .foregroundStyle(Palette.secondaryText)
            .padding(.horizontal, Spacing.lg)
            .padding(.top, Spacing.sm)
    }

    private func labeledField(_ label: String, text: Binding<String>,
                              contentType: UITextContentType?,
                              capitalization: TextInputAutocapitalization = .words,
                              prompt: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: Spacing.xxs) {
            Text(label)
                .font(Typography.fieldLabel)
                .foregroundStyle(Palette.secondaryText)
            TextField(prompt ?? label, text: text)
                .textContentType(contentType)
                .textInputAutocapitalization(capitalization)
                .autocorrectionDisabled()
        }
        .padding(.horizontal, Spacing.lg)
        .padding(.vertical, Spacing.sm)
        .frame(minHeight: 66)
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
        let login: PlaintextCipher.Login?
        if isLogin {
            login = PlaintextCipher.Login(
                username: username.nilIfEmpty,
                password: password.nilIfEmpty,
                totp: totp.nilIfEmpty,
                uris: uris.compactMap { value in
                    value.nilIfEmpty.map { PlaintextCipher.Uri(uri: $0) }
                }
            )
        } else {
            login = nil
        }
        return PlaintextCipher(
            id: existing?.id,
            type: type,
            name: name.trimmingCharacters(in: .whitespacesAndNewlines),
            notes: notes.nilIfEmpty,
            folderID: existing?.folderID,
            favorite: favorite,
            reprompt: existing?.reprompt ?? 0,
            login: login
        )
    }
}

private extension String {
    var nilIfEmpty: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
