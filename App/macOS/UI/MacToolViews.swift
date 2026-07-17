import SwiftUI
import UIShared
import DesignSystem
import Generators

@available(macOS 27.0, *)
struct MacToolColumnView: View {
    let destination: MacDestination

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(destination.title)
                    .font(.system(size: 16, weight: .bold))
                    .foregroundStyle(.white)
                Spacer()
            }
            .padding(.horizontal, 14)
            .frame(height: 50)
            Divider().overlay(.black.opacity(0.4))

            VStack(spacing: 1) {
                HStack(spacing: 10) {
                    Image(systemName: destination.systemImage)
                        .font(.system(size: 14, weight: .medium))
                        .foregroundStyle(.white)
                        .frame(width: 30, height: 30)
                        .background(MacOpenVaultStyle.selectedBlue, in: Circle())
                    VStack(alignment: .leading, spacing: 1) {
                        Text(destination.title)
                            .font(.system(size: 13.5, weight: .semibold))
                        Text(subtitle)
                            .font(.system(size: 11.5))
                            .foregroundStyle(.white.opacity(0.72))
                    }
                    Spacer()
                }
                .foregroundStyle(.white)
                .padding(.horizontal, 9)
                .frame(minHeight: 48)
                .background(MacOpenVaultStyle.selected, in: RoundedRectangle(cornerRadius: 8))
            }
            .padding(8)
            Spacer()
        }
        .background(MacOpenVaultStyle.list)
    }

    private var subtitle: String {
        switch destination {
        case .generator: "密码、口令与用户名"
        case .send: "端到端加密分享"
        case .security: "保险库安全状态"
        case .settings: "安全、同步与外观"
        default: "OpenVault"
        }
    }
}

@available(macOS 27.0, *)
struct MacGeneratorView: View {
    @State private var model = GeneratorModel()
    @State private var copiedMessage: String?
    @State private var toastID = UUID()

    var body: some View {
        @Bindable var model = model

        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header

                Picker("模式", selection: $model.mode) {
                    Text("密码").tag(GeneratorModel.Mode.password)
                    Text("口令").tag(GeneratorModel.Mode.passphrase)
                    Text("用户名").tag(GeneratorModel.Mode.username)
                }
                .pickerStyle(.segmented)
                .labelsHidden()

                resultCard
                optionsCard

                if !model.history.isEmpty {
                    historyCard
                }
            }
            .padding(24)
            .frame(maxWidth: 720, alignment: .leading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(MacOpenVaultStyle.detail)
        .overlay(alignment: .bottom) {
            if let copiedMessage {
                GlassToast(copiedMessage)
                    .padding(.bottom, 24)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .task {
            guard model.generated.isEmpty else { return }
            model.passphraseOptions = PassphraseGeneratorOptions(
                wordCount: 3,
                separator: "-",
                capitalize: true,
                includeNumber: true
            )
            model.regenerate()
        }
    }

    private var header: some View {
        HStack(spacing: 13) {
            Image(systemName: "sparkles")
                .font(.system(size: 21, weight: .medium))
                .foregroundStyle(.white)
                .frame(width: 50, height: 50)
                .background(MacOpenVaultStyle.selectedBlue, in: Circle())
            VStack(alignment: .leading, spacing: 2) {
                Text("生成器")
                    .font(.system(size: 20, weight: .bold))
                    .foregroundStyle(.white)
                Text("使用本机安全随机源生成凭据")
                    .font(.system(size: 12))
                    .foregroundStyle(MacOpenVaultStyle.secondary)
            }
        }
    }

    private var resultCard: some View {
        OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 18) {
            VStack(alignment: .leading, spacing: 14) {
                if let error = model.errorMessage {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(Color.orange)
                } else {
                    Text(model.generated.isEmpty ? "—" : model.generated)
                        .font(.system(size: 20, weight: .medium, design: .monospaced))
                        .foregroundStyle(.white.opacity(0.96))
                        .textSelection(.enabled)
                        .privacySensitive()
                        .frame(maxWidth: .infinity, minHeight: 38, alignment: .leading)
                }

                if model.mode == .password {
                    strengthMeter
                }

                HStack(spacing: 10) {
                    Button {
                        model.regenerate(recordInHistory: true)
                    } label: {
                        Label("重新生成", systemImage: "arrow.clockwise")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.glass)

                    Button {
                        guard let value = model.copyGenerated() else { return }
                        MacClipboard.copy(value)
                        showToast("已拷贝生成结果")
                    } label: {
                        Label("拷贝", systemImage: "doc.on.doc")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.glassProminent)
                    .disabled(model.generated.isEmpty)
                }
            }
        }
        .overlay { cardStroke }
    }

    @ViewBuilder
    private var optionsCard: some View {
        OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 18) {
            switch model.mode {
            case .password:
                passwordOptions
            case .passphrase:
                passphraseOptions
            case .username:
                usernameOptions
            }
        }
        .overlay { cardStroke }
    }

    private var passwordOptions: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("长度")
                Slider(value: passwordLength, in: 8...40, step: 1)
                Text(model.passwordOptions.length, format: .number)
                    .monospacedDigit()
                    .frame(width: 28, alignment: .trailing)
            }
            optionToggle("大写字母", value: passwordOption(\.useUppercase))
            optionToggle("小写字母", value: passwordOption(\.useLowercase))
            optionToggle("数字", value: passwordOption(\.useNumbers))
            optionToggle("符号", value: passwordOption(\.useSpecial))
            optionToggle("避开易混淆字符", value: passwordOption(\.avoidAmbiguous))
        }
        .font(.system(size: 13.5))
        .foregroundStyle(.white.opacity(0.9))
    }

    private var passphraseOptions: some View {
        VStack(alignment: .leading, spacing: 14) {
            Stepper("单词数量：\(model.passphraseOptions.wordCount)", value: Binding(
                get: { model.passphraseOptions.wordCount },
                set: { model.passphraseOptions.wordCount = $0; model.regenerate() }
            ), in: 3...8)
            TextField("分隔符", text: Binding(
                get: { model.passphraseOptions.separator },
                set: { model.passphraseOptions.separator = $0; model.regenerate() }
            ))
            optionToggle("首字母大写", value: passphraseOption(\.capitalize))
            optionToggle("包含数字", value: passphraseOption(\.includeNumber))
        }
        .font(.system(size: 13.5))
        .foregroundStyle(.white.opacity(0.9))
    }

    private var usernameOptions: some View {
        VStack(alignment: .leading, spacing: 14) {
            TextField("别名前缀", text: Binding(
                get: { model.usernameBase },
                set: { model.usernameBase = $0; model.regenerate() }
            ))
            TextField("域名", text: Binding(
                get: { model.usernameDomain },
                set: { model.usernameDomain = $0; model.regenerate() }
            ))
            Stepper("随机后缀：\(model.usernameSuffixLength) 位", value: Binding(
                get: { model.usernameSuffixLength },
                set: { model.usernameSuffixLength = $0; model.regenerate() }
            ), in: 2...12)
        }
        .font(.system(size: 13.5))
        .foregroundStyle(.white.opacity(0.9))
    }

    private var historyCard: some View {
        OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 18) {
            DisclosureGroup("生成历史") {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(Array(model.history.prefix(8).enumerated()), id: \.offset) { _, value in
                        Text(value)
                            .font(.system(size: 12.5, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                            .privacySensitive()
                    }
                }
                .padding(.top, 10)
            }
            .foregroundStyle(.white.opacity(0.88))
        }
        .overlay { cardStroke }
    }

    private var strengthMeter: some View {
        let score = model.passwordOptions.length + enabledSetCount * 3
        let label = score < 20 ? "中等" : (score < 30 ? "强" : "极强")
        let color: Color = score < 20 ? .orange : (score < 30 ? .green : MacOpenVaultStyle.totp)
        return VStack(alignment: .leading, spacing: 5) {
            GeometryReader { proxy in
                Capsule()
                    .fill(.white.opacity(0.09))
                    .overlay(alignment: .leading) {
                        Capsule()
                            .fill(color)
                            .frame(width: proxy.size.width * min(Double(score) / 42, 1))
                    }
            }
            .frame(height: 4)
            Text("强度：\(label)")
                .font(.system(size: 11.5, weight: .semibold))
                .foregroundStyle(color)
        }
    }

    private var enabledSetCount: Int {
        [model.passwordOptions.useLowercase, model.passwordOptions.useUppercase,
         model.passwordOptions.useNumbers, model.passwordOptions.useSpecial]
            .count(where: { $0 })
    }

    private var passwordLength: Binding<Double> {
        Binding(
            get: { Double(model.passwordOptions.length) },
            set: { model.passwordOptions.length = Int($0); model.regenerate() }
        )
    }

    private func passwordOption(_ keyPath: WritableKeyPath<PasswordGeneratorOptions, Bool>) -> Binding<Bool> {
        Binding(
            get: { model.passwordOptions[keyPath: keyPath] },
            set: {
                model.passwordOptions[keyPath: keyPath] = $0
                if !model.passwordOptions.useLowercase,
                   !model.passwordOptions.useUppercase,
                   !model.passwordOptions.useNumbers,
                   !model.passwordOptions.useSpecial {
                    model.passwordOptions.useLowercase = true
                }
                model.regenerate()
            }
        )
    }

    private func passphraseOption(_ keyPath: WritableKeyPath<PassphraseGeneratorOptions, Bool>) -> Binding<Bool> {
        Binding(
            get: { model.passphraseOptions[keyPath: keyPath] },
            set: { model.passphraseOptions[keyPath: keyPath] = $0; model.regenerate() }
        )
    }

    private func optionToggle(_ title: String, value: Binding<Bool>) -> some View {
        Toggle(title, isOn: value)
            .toggleStyle(.switch)
    }

    private var cardStroke: some View {
        RoundedRectangle(cornerRadius: CornerRadius.macCard, style: .continuous)
            .stroke(.white.opacity(0.07), lineWidth: 0.5)
    }

    private func showToast(_ message: String) {
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

@available(macOS 27.0, *)
struct MacSendView: View {
    var body: some View {
        unavailable(
            title: "暂无发送项目",
            systemImage: "paperplane",
            description: "当前服务层尚未提供 Bitwarden Send API。这里不会显示示例内容；接入端到端加密发送服务后，真实项目会出现在此处。"
        )
    }
}

@available(macOS 27.0, *)
struct MacSecurityView: View {
    var body: some View {
        unavailable(
            title: "安全报告尚不可用",
            systemImage: "shield.lefthalf.filled",
            description: "当前保险库服务没有泄露检测、弱密码报告或重复密码数据，因此 OpenVault 不会伪造安全结论。"
        )
    }
}

@available(macOS 27.0, *)
private func unavailable(title: String, systemImage: String, description: String) -> some View {
    ContentUnavailableView(title, systemImage: systemImage, description: Text(description))
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(MacOpenVaultStyle.detail)
}
