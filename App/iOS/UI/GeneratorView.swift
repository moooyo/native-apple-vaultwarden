import SwiftUI
import UIShared
import DesignSystem
import Generators

@available(iOS 27.0, *)
public struct GeneratorView: View {
    @State private var model: GeneratorModel
    @State private var toastMessage: String?
    @State private var toastTask: Task<Void, Never>?

    public init(model: GeneratorModel = GeneratorModel()) {
        _model = State(initialValue: model)
    }

    public var body: some View {
        ScrollView {
            LazyVStack(spacing: Spacing.lg) {
                modePicker
                resultCard

                switch model.mode {
                case .password: passwordOptions
                case .passphrase: passphraseOptions
                case .username: usernameOptions
                }

                actionButtons

                if !model.history.isEmpty {
                    historyCard
                }

                if let errorMessage = model.errorMessage {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .font(.subheadline)
                        .foregroundStyle(Palette.warning)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(Spacing.lg)
        }
        .background(Palette.groupedBackground)
        .scrollEdgeEffectStyle(.soft, for: .all)
        .navigationTitle("生成器")
        .task { if model.generated.isEmpty { model.regenerate() } }
        .copyToast(toastMessage)
        .onDisappear { toastTask?.cancel() }
    }

    private var modePicker: some View {
        Picker("生成类型", selection: $model.mode) {
            Text("密码").tag(GeneratorModel.Mode.password)
            Text("口令").tag(GeneratorModel.Mode.passphrase)
            Text("用户名").tag(GeneratorModel.Mode.username)
        }
        .pickerStyle(.segmented)
        .accessibilityLabel("生成类型")
    }

    private var resultCard: some View {
        OpenVaultCard {
            VStack(alignment: .leading, spacing: Spacing.lg) {
                Group {
                    if model.mode == .password {
                        coloredPassword(model.generated)
                    } else {
                        Text(model.generated.isEmpty ? "—" : model.generated)
                            .foregroundStyle(Palette.primaryText)
                    }
                }
                .font(.system(size: 19, weight: .regular, design: .monospaced))
                .textSelection(.enabled)
                .lineLimit(3)
                .minimumScaleFactor(0.72)
                .privacySensitive()

                if model.mode == .password {
                    VStack(alignment: .leading, spacing: Spacing.xs) {
                        GeometryReader { proxy in
                            ZStack(alignment: .leading) {
                                Capsule().fill(Palette.separator.opacity(0.5))
                                Capsule()
                                    .fill(strengthColor)
                                    .frame(width: proxy.size.width * strengthFraction)
                            }
                        }
                        .frame(height: 4)
                        Text(strengthLabel)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(strengthColor)
                    }
                }
            }
        }
    }

    private var passwordOptions: some View {
        OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                VStack(alignment: .leading, spacing: Spacing.sm) {
                    HStack {
                        Text("长度")
                        Spacer()
                        Text(model.passwordOptions.length, format: .number)
                            .foregroundStyle(Palette.secondaryText)
                            .monospacedDigit()
                    }
                    Slider(value: passwordLength, in: 8...40, step: 1)
                        .accessibilityValue("\(model.passwordOptions.length) 位")
                }
                .padding(Spacing.lg)

                optionDivider
                characterToggle("大写字母", binding: $model.passwordOptions.useUppercase)
                optionDivider
                characterToggle("小写字母", binding: $model.passwordOptions.useLowercase)
                optionDivider
                characterToggle("数字", binding: $model.passwordOptions.useNumbers)
                optionDivider
                characterToggle("符号", binding: $model.passwordOptions.useSpecial)
                optionDivider
                optionToggle("避开易混淆字符", binding: $model.passwordOptions.avoidAmbiguous)
            }
        }
    }

    private var passphraseOptions: some View {
        OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                HStack {
                    Text("单词数量")
                    Spacer()
                    Stepper(value: $model.passphraseOptions.wordCount, in: 3...8) {
                        Text(model.passphraseOptions.wordCount, format: .number)
                            .monospacedDigit()
                    }
                    .labelsHidden()
                    Text(model.passphraseOptions.wordCount, format: .number)
                        .foregroundStyle(Palette.secondaryText)
                        .frame(width: 24)
                }
                .padding(.horizontal, Spacing.lg)
                .frame(minHeight: 56)
                .onChange(of: model.passphraseOptions.wordCount) { _, _ in model.regenerate() }

                optionDivider
                HStack {
                    Text("分隔符")
                    Spacer()
                    Picker("分隔符", selection: $model.passphraseOptions.separator) {
                        Text("连字符 -").tag("-")
                        Text("空格").tag(" ")
                        Text("句点 .").tag(".")
                        Text("下划线 _").tag("_")
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)
                }
                .padding(.horizontal, Spacing.lg)
                .frame(minHeight: 54)
                .onChange(of: model.passphraseOptions.separator) { _, _ in model.regenerate() }

                optionDivider
                optionToggle("首字母大写", binding: $model.passphraseOptions.capitalize)
                optionDivider
                optionToggle("包含数字", binding: $model.passphraseOptions.includeNumber)
            }
        }
    }

    private var usernameOptions: some View {
        OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                generatorField("基础名称", text: $model.usernameBase)
                optionDivider
                generatorField("邮箱域名", text: $model.usernameDomain)
                optionDivider
                HStack {
                    Text("随机后缀")
                    Spacer()
                    Stepper(value: $model.usernameSuffixLength, in: 2...12) {
                        Text("\(model.usernameSuffixLength) 位")
                            .foregroundStyle(Palette.secondaryText)
                            .monospacedDigit()
                    }
                }
                .padding(.horizontal, Spacing.lg)
                .frame(minHeight: 56)
                .onChange(of: model.usernameSuffixLength) { _, _ in model.regenerate() }
            }
        }
    }

    private var actionButtons: some View {
        HStack(spacing: Spacing.md) {
            actionButton("重新生成", systemImage: "arrow.clockwise") {
                model.regenerate(recordInHistory: true)
            }
            actionButton("复制", systemImage: "doc.on.doc") {
                guard let value = model.copyGenerated() else { return }
                Clipboard.copy(value)
                showToast("已拷贝\(modeName)")
            }
            .disabled(model.generated.isEmpty)
        }
    }

    private var historyCard: some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            OpenVaultSectionTitle("生成历史")
            OpenVaultCard(padding: 0) {
                VStack(spacing: 0) {
                    ForEach(Array(model.history.prefix(8).enumerated()), id: \.offset) { index, value in
                        Button {
                            Clipboard.copy(value)
                            showToast("已拷贝历史记录")
                        } label: {
                            HStack {
                                Text(value)
                                    .font(.system(.subheadline, design: .monospaced))
                                    .foregroundStyle(Palette.primaryText)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                    .privacySensitive()
                                Spacer()
                                Image(systemName: "doc.on.doc")
                                    .foregroundStyle(Palette.accent)
                            }
                            .padding(.horizontal, Spacing.lg)
                            .frame(minHeight: 50)
                        }
                        .buttonStyle(.plain)
                        if index < min(model.history.count, 8) - 1 {
                            Divider().padding(.leading, Spacing.lg)
                        }
                    }
                }
            }
        }
    }

    private var passwordLength: Binding<Double> {
        Binding(
            get: { Double(model.passwordOptions.length) },
            set: {
                model.passwordOptions.length = Int($0.rounded())
                model.regenerate()
            }
        )
    }

    private var optionDivider: some View {
        Divider().padding(.leading, Spacing.lg)
    }

    private func optionToggle(_ title: String, binding: Binding<Bool>) -> some View {
        Toggle(title, isOn: binding)
            .padding(.horizontal, Spacing.lg)
            .frame(minHeight: 52)
            .onChange(of: binding.wrappedValue) { _, _ in model.regenerate() }
    }

    private func characterToggle(_ title: String, binding: Binding<Bool>) -> some View {
        Toggle(title, isOn: binding)
            .padding(.horizontal, Spacing.lg)
            .frame(minHeight: 52)
            .onChange(of: binding.wrappedValue) { _, _ in
                if !model.passwordOptions.useUppercase,
                   !model.passwordOptions.useLowercase,
                   !model.passwordOptions.useNumbers,
                   !model.passwordOptions.useSpecial {
                    model.passwordOptions.useLowercase = true
                }
                model.regenerate()
            }
    }

    private func generatorField(_ label: String, text: Binding<String>) -> some View {
        HStack {
            Text(label)
            Spacer()
            TextField(label, text: text)
                .multilineTextAlignment(.trailing)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .frame(maxWidth: 190)
        }
        .padding(.horizontal, Spacing.lg)
        .frame(minHeight: 56)
        .onChange(of: text.wrappedValue) { _, _ in model.regenerate() }
    }

    private func actionButton(_ title: String, systemImage: String,
                              action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: systemImage)
                .font(.headline)
                .frame(maxWidth: .infinity, minHeight: 50)
                .background(Palette.controlFill,
                            in: RoundedRectangle(cornerRadius: CornerRadius.button,
                                                 style: .continuous))
        }
        .buttonStyle(.plain)
        .foregroundStyle(Palette.accent)
    }

    private func coloredPassword(_ value: String) -> Text {
        var result = AttributedString()
        for character in value {
            let color: Color
            if character.isNumber { color = Palette.accent }
            else if character.isLetter { color = Palette.primaryText }
            else { color = Palette.danger }
            var part = AttributedString(String(character))
            part.foregroundColor = color
            result.append(part)
        }
        return Text(result)
    }

    private var enabledSetCount: Int {
        [model.passwordOptions.useUppercase, model.passwordOptions.useLowercase,
         model.passwordOptions.useNumbers, model.passwordOptions.useSpecial]
            .filter { $0 }.count
    }

    private var strengthScore: Double {
        min(1, Double(model.passwordOptions.length + enabledSetCount * 3) / 42)
    }

    private var strengthFraction: Double { max(0.16, strengthScore) }

    private var strengthLabel: String {
        switch strengthScore {
        case ..<0.48: "中等"
        case ..<0.72: "强"
        default: "极强"
        }
    }

    private var strengthColor: Color {
        switch strengthScore {
        case ..<0.48: Palette.warning
        case ..<0.72: Palette.success
        default: Palette.teal
        }
    }

    private var modeName: String {
        switch model.mode {
        case .password: "密码"
        case .passphrase: "口令"
        case .username: "用户名"
        }
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
