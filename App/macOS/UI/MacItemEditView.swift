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
    @State private var username: String
    @State private var password: String
    @State private var totp: String
    @State private var uri: String
    @State private var notes: String
    @State private var favorite: Bool
    @State private var revealPassword = false
    @State private var revealTOTP = false
    @State private var isSaving = false
    @State private var errorMessage: String?

    init(vault: VaultService, existing: PlaintextCipher? = nil,
         onSaved: @escaping (String) -> Void) {
        self.vault = vault
        self.existing = existing
        self.onSaved = onSaved
        _type = State(initialValue: existing?.type ?? CipherType.login.rawValue)
        _name = State(initialValue: existing?.name ?? "")
        _username = State(initialValue: existing?.login?.username ?? "")
        _password = State(initialValue: existing?.login?.password ?? "")
        _totp = State(initialValue: existing?.login?.totp ?? "")
        _uri = State(initialValue: existing?.login?.uris.first?.uri ?? "")
        _notes = State(initialValue: existing?.notes ?? "")
        _favorite = State(initialValue: existing?.favorite ?? false)
    }

    private var isLogin: Bool { type == CipherType.login.rawValue }
    private var canSave: Bool { name.nilIfBlank != nil && !isSaving }

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
                                }
                                .labelsHidden()
                                .frame(width: 130)
                            }
                            rowDivider
                            editTextField("名称", text: $name, prompt: "条目名称")
                            rowDivider
                            editRow("置顶") {
                                Toggle("", isOn: $favorite).labelsHidden()
                            }
                        }
                    }

                    if isLogin {
                        sectionTitle("登录凭据")
                        card {
                            VStack(spacing: 0) {
                                editTextField("用户名", text: $username, prompt: "用户名或邮箱")
                                rowDivider
                                HStack(spacing: 12) {
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text("密码").fieldLabel()
                                        Group {
                                            if revealPassword {
                                                TextField("密码", text: $password)
                                            } else {
                                                SecureField("密码", text: $password)
                                            }
                                        }
                                        .font(.system(size: 13.5, design: .monospaced))
                                        .textFieldStyle(.plain)
                                    }
                                    Spacer()
                                    Button { revealPassword.toggle() } label: {
                                        Image(systemName: revealPassword ? "eye.slash" : "eye")
                                    }
                                    .buttonStyle(.borderless)
                                    .help(revealPassword ? "隐藏密码" : "显示密码")
                                }
                                .padding(.horizontal, 15)
                                .frame(minHeight: 54)
                                rowDivider
                                HStack(spacing: 12) {
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text("验证器密钥").fieldLabel()
                                        Group {
                                            if revealTOTP {
                                                TextField("Base32 或 otpauth://", text: $totp)
                                            } else {
                                                SecureField("Base32 或 otpauth://", text: $totp)
                                            }
                                        }
                                        .font(.system(size: 13.5, design: .monospaced))
                                        .textFieldStyle(.plain)
                                        .privacySensitive()
                                    }
                                    Spacer()
                                    Button { revealTOTP.toggle() } label: {
                                        Image(systemName: revealTOTP ? "eye.slash" : "eye")
                                    }
                                    .buttonStyle(.borderless)
                                    .help(revealTOTP ? "隐藏验证器密钥" : "显示验证器密钥")
                                }
                                .padding(.horizontal, 15)
                                .frame(minHeight: 54)
                            }
                        }

                        sectionTitle("网站")
                        card {
                            editTextField("网址", text: $uri, prompt: "https://example.com")
                        }
                    }

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
        .frame(width: 520, height: 620)
        .background(MacOpenVaultStyle.detail)
    }

    private var header: some View {
        HStack {
            Button("取消") { dismiss() }
                .keyboardShortcut(.cancelAction)
            Spacer()
            Text(existing == nil ? "新建条目" : "编辑条目")
                .font(.system(size: 15, weight: .semibold))
            Spacer()
            Button(action: save) {
                if isSaving {
                    ProgressView().controlSize(.small)
                } else {
                    Text("存储")
                }
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
            Text(label)
                .font(.system(size: 13.5))
            Spacer()
            accessory()
        }
        .padding(.horizontal, 15)
        .frame(minHeight: 50)
    }

    private func editTextField(_ label: String, text: Binding<String>, prompt: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).fieldLabel()
            TextField(prompt, text: text)
                .textFieldStyle(.plain)
                .font(.system(size: 13.5))
        }
        .padding(.horizontal, 15)
        .frame(minHeight: 54)
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
        let login: PlaintextCipher.Login? = isLogin
            ? PlaintextCipher.Login(
                username: username.nilIfBlank,
                password: password.nilIfBlank,
                totp: totp.nilIfBlank,
                uris: uri.nilIfBlank.map { [PlaintextCipher.Uri(uri: $0)] } ?? []
            )
            : nil
        return PlaintextCipher(
            id: existing?.id,
            type: type,
            name: name.trimmingCharacters(in: .whitespacesAndNewlines),
            notes: notes.nilIfBlank,
            folderID: existing?.folderID,
            favorite: favorite,
            reprompt: existing?.reprompt ?? 0,
            login: login
        )
    }
}

@available(macOS 27.0, *)
private extension View {
    func fieldLabel() -> some View {
        font(.system(size: 11)).foregroundStyle(.white.opacity(0.45))
    }
}
