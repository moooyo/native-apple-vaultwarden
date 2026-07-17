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
    @State private var showingEdit = false
    @State private var showInspector = false
    @State private var copiedMessage: String?
    @State private var toastID = UUID()

    init(cipher: PlaintextCipher, vault: VaultService, onChanged: @escaping () -> Void) {
        self.cipher = cipher
        self.vault = vault
        self.onChanged = onChanged
    }

    private var supportsEditing: Bool {
        let type = CipherType(rawValue: cipher.type)
        return type == .login || type == .secureNote
    }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            ScrollView {
                VStack(alignment: .leading, spacing: 11) {
                    header

                    if let login = cipher.login {
                        loginCard(login, at: context.date)
                    }

                    if let notes = cipher.notes?.nilIfBlank {
                        notesCard(notes)
                    }

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
            inspector
                .inspectorColumnWidth(min: 230, ideal: 270, max: 340)
        }
        .sheet(isPresented: $showingEdit) {
            MacItemEditView(vault: vault, existing: cipher) { _ in
                showingEdit = false
                onChanged()
            }
        }
        .onChange(of: cipher.id) { _, _ in revealPassword = false }
    }

    private var header: some View {
        HStack(spacing: 13) {
            BrandBadge(cipher.name, diameter: 50)
            VStack(alignment: .leading, spacing: 2) {
                Text(cipher.name.nilIfBlank ?? "未命名条目")
                    .font(.system(size: 20, weight: .bold))
                    .foregroundStyle(.white)
                HStack(spacing: 4) {
                    Text(cipher.macTypeLabel)
                    if cipher.favorite {
                        Text("·")
                        Label("已置顶", systemImage: "star.fill")
                            .labelStyle(.titleOnly)
                    }
                }
                .font(.system(size: 12))
                .foregroundStyle(MacOpenVaultStyle.secondary)
            }
            Spacer(minLength: 12)

            Button { showInspector.toggle() } label: {
                Label("信息", systemImage: "info.circle")
                    .font(.system(size: 12.5, weight: .semibold))
                    .padding(.horizontal, 4)
                    .frame(height: 30)
            }
            .buttonStyle(.glass)

            if supportsEditing {
                Button { showingEdit = true } label: {
                    Label("编辑", systemImage: "pencil")
                        .font(.system(size: 12.5, weight: .semibold))
                        .padding(.horizontal, 4)
                        .frame(height: 30)
                }
                .buttonStyle(.glassProminent)
            }
        }
        .padding(.bottom, 5)
    }

    private func loginCard(_ login: PlaintextCipher.Login, at date: Date) -> some View {
        OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 0) {
            VStack(spacing: 0) {
                if let username = login.username?.nilIfBlank {
                    copyField(label: "用户名", value: username, message: "已拷贝用户名")
                    fieldDivider
                }

                if let password = login.password?.nilIfBlank {
                    passwordField(password)
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
        .overlay { cardStroke }
    }

    private func copyField(label: String, value: String, message: String) -> some View {
        HStack(spacing: 12) {
            fieldValue(label: label, value: value)
            Spacer(minLength: 8)
            copyButton(value, message: message, label: "拷贝\(label)")
        }
        .padding(.horizontal, 15)
        .frame(minHeight: 50)
    }

    private func passwordField(_ password: String) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("密码")
                    .font(.system(size: 11))
                    .foregroundStyle(.white.opacity(0.45))
                Text(revealPassword ? password : String(repeating: "•", count: min(max(password.count, 8), 16)))
                    .font(.system(size: 13.5, design: revealPassword ? .monospaced : .default))
                    .tracking(revealPassword ? 0 : 2.5)
                    .foregroundStyle(.white.opacity(0.94))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                    .privacySensitive()
            }
            Spacer(minLength: 8)
            Button { revealPassword.toggle() } label: {
                Image(systemName: revealPassword ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
            .foregroundStyle(MacOpenVaultStyle.selectedBlue)
            .help(revealPassword ? "隐藏密码" : "显示密码")
            copyButton(password, message: "已拷贝密码", label: "拷贝密码")
        }
        .padding(.horizontal, 15)
        .frame(minHeight: 50)
    }

    private func totpField(_ configuration: TOTPConfiguration, at date: Date) -> some View {
        let raw = TOTP.code(for: configuration, at: date)
        let code = OTPRingMath.formatCode(raw)
        let seconds = TOTP.secondsRemaining(for: configuration, at: date)
        let progress = OTPRingMath.progress(secondsRemaining: seconds, period: configuration.period)

        return HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("验证码")
                    .font(.system(size: 11))
                    .foregroundStyle(.white.opacity(0.45))
                HStack(spacing: 9) {
                    Text(code)
                        .font(.system(size: 15, weight: .medium, design: .monospaced))
                        .tracking(1.5)
                        .monospacedDigit()
                        .foregroundStyle(.white.opacity(0.94))
                        .contentTransition(.numericText())
                        .privacySensitive()
                    CountdownRing(progress: progress, size: 17, lineWidth: 2.4, tint: MacOpenVaultStyle.totp)
                }
            }
            Spacer(minLength: 8)
            copyButton(raw, message: "已拷贝验证码", label: "拷贝验证码")
        }
        .padding(.horizontal, 15)
        .frame(minHeight: 50)
    }

    private func websiteField(_ value: String) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("网站")
                    .font(.system(size: 11))
                    .foregroundStyle(.white.opacity(0.45))
                if let url = webURL(value) {
                    Link(value, destination: url)
                        .font(.system(size: 13.5))
                        .foregroundStyle(Color(red: 121 / 255, green: 186 / 255, blue: 1))
                        .lineLimit(1)
                        .truncationMode(.middle)
                } else {
                    Text(value)
                        .font(.system(size: 13.5))
                        .foregroundStyle(.white.opacity(0.9))
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            Spacer(minLength: 8)
            copyButton(value, message: "已拷贝网站", label: "拷贝网站")
        }
        .padding(.horizontal, 15)
        .frame(minHeight: 50)
    }

    private func notesCard(_ notes: String) -> some View {
        OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 15) {
            VStack(alignment: .leading, spacing: 4) {
                Text("备注")
                    .font(.system(size: 11))
                    .foregroundStyle(.white.opacity(0.45))
                Text(notes)
                    .font(.system(size: 12.5))
                    .lineSpacing(3)
                    .foregroundStyle(.white.opacity(0.84))
                    .textSelection(.enabled)
            }
        }
        .overlay { cardStroke }
    }

    private var availabilityCard: some View {
        OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 0) {
            HStack(spacing: 10) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 17))
                    .foregroundStyle(.white.opacity(0.52))
                    .frame(width: 24, height: 24)
                Text("尚未运行安全检查")
                    .font(.system(size: 13.5))
                    .foregroundStyle(.white.opacity(0.88))
                Spacer()
                Text("当前服务层未提供泄露报告")
                    .font(.system(size: 12))
                    .foregroundStyle(.white.opacity(0.42))
            }
            .padding(.horizontal, 15)
            .frame(minHeight: 46)
        }
        .overlay { cardStroke }
    }

    private var footer: some View {
        HStack {
            Text("端到端加密 · \(cipher.macTypeLabel)")
            Spacer()
            if let id = cipher.id {
                Text(id)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(maxWidth: 180)
            }
        }
        .font(.system(size: 11))
        .foregroundStyle(.white.opacity(0.36))
        .padding(.top, 4)
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
            }
            Section("密码历史") {
                Text("当前服务层尚未提供密码历史。")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }

    private var fieldDivider: some View {
        Divider().overlay(MacOpenVaultStyle.hairline).padding(.leading, 15)
    }

    private var cardStroke: some View {
        RoundedRectangle(cornerRadius: CornerRadius.macCard, style: .continuous)
            .stroke(.white.opacity(0.07), lineWidth: 0.5)
    }

    private func fieldValue(label: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(size: 11))
                .foregroundStyle(.white.opacity(0.45))
            Text(value)
                .font(.system(size: 13.5))
                .foregroundStyle(.white.opacity(0.94))
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
        }
    }

    private func copyButton(_ value: String, message: String, label: String) -> some View {
        Button {
            copy(value, message: message)
        } label: {
            Image(systemName: "doc.on.doc")
        }
        .buttonStyle(.borderless)
        .foregroundStyle(MacOpenVaultStyle.selectedBlue)
        .help(label)
        .accessibilityLabel(label)
    }

    private func totpConfiguration(_ login: PlaintextCipher.Login) -> TOTPConfiguration? {
        guard let raw = login.totp?.nilIfBlank else { return nil }
        return try? TOTP.configuration(from: raw)
    }

    private func webURL(_ value: String) -> URL? {
        if let url = URL(string: value), let scheme = url.scheme, ["http", "https"].contains(scheme.lowercased()) {
            return url
        }
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
}
