import SwiftUI
import DesignSystem
import Generators
import UIShared
import VaultRepository

private extension GeneratorModel.Mode {
    var titleKey: String {
        switch self {
        case .password: "密码"
        case .passphrase: "口令"
        case .username: "用户名"
        }
    }
}

private struct GeneratorCard<Content: View>: View {
    let wide: Bool
    let padding: CGFloat
    @ViewBuilder let content: () -> Content

    var body: some View {
        #if os(macOS)
        MacDetailCard { content().padding(padding) }
        #else
        OpenVaultCard(cornerRadius: wide ? CornerRadius.iPadCard : CornerRadius.iPhoneCard,
                      padding: padding, content: content)
        #endif
    }
}

struct GenerationModePicker: View {
    @Bindable var model: GeneratorModel
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    var body: some View {
        let picker = Picker("生成类型", selection: $model.mode) {
            ForEach(GeneratorModel.Mode.allCases, id: \.self) { mode in
                Text(LocalizedStringKey(mode.titleKey)).tag(mode)
            }
        }
        if dynamicTypeSize.isAccessibilitySize {
            picker.pickerStyle(.menu)
        } else {
            #if os(macOS)
            MacSegmentedPicker(MacLocalization.text("生成类型"), options: GeneratorModel.Mode.allCases, selection: $model.mode) {
                MacLocalization.text($0.titleKey)
            }
            #else
            picker.pickerStyle(.segmented).labelsHidden()
            #endif
        }
    }
}

struct GenerationResultCard: View {
    let model: GeneratorModel
    var wide = false
    var centered = false
    @ScaledMetric(relativeTo: .title2) private var resultSize: CGFloat = 24
    @ScaledMetric(relativeTo: .title) private var wideResultSize: CGFloat = 28

    var body: some View {
        GeneratorCard(wide: wide, padding: wide || centered ? 22 : 18) {
            VStack(alignment: .leading, spacing: Spacing.md) {
                Group {
                    if let error = model.errorMessage {
                        Label(LocalizedStringKey(error), systemImage: "exclamationmark.triangle")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    } else {
                        ColoredSecretText(model.generated, usage: .generated)
                            .font(.system(size: wide ? wideResultSize : resultSize, weight: .semibold, design: .monospaced))
                            .multilineTextAlignment(centered ? .center : .leading)
                            .fixedSize(horizontal: false, vertical: true)
                            .privacySensitive()
                    }
                }
                .frame(maxWidth: .infinity, minHeight: wide ? 114 : 64,
                       alignment: centered ? .top : .topLeading)

                if let level = model.strengthLevel, let bits = model.estimatedEntropy {
                    let caption = Text("约 \(bits) 位熵")
                    SecretStrengthMeter(strength: .level(forRawScore: level), localizedCaption: caption)
                } else if model.mode == .username && !model.generated.isEmpty {
                    Text("邮箱别名")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

struct GenerationActions: View {
    let model: GeneratorModel
    let copy: (String) -> Void
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    var body: some View {
        let layout = dynamicTypeSize.isAccessibilitySize
            ? AnyLayout(VStackLayout(spacing: Spacing.sm)) : AnyLayout(HStackLayout(spacing: Spacing.md))
        layout {
            Button {
                model.regenerate(recordInHistory: true)
            } label: {
                actionLabel("重新生成", symbol: "arrow.clockwise")
            }
            .buttonStyle(.bordered)
            InlineCopyButton(action: {
                if let value = model.copyGenerated() { copy(value) }
            }) { copied in
                actionLabel(copied ? "已拷贝" : "拷贝", symbol: copied ? "checkmark" : "doc.on.doc")
            }
            .vaultProminentButtonStyle()
            .disabled(model.generated.isEmpty)
            .id(model.generationRevision)
        }
        .disabled(model.isHistoryBusy)
        #if os(iOS)
        .controlSize(.large)
        .buttonBorderShape(.capsule)
        #endif
    }

    @ViewBuilder
    private func actionLabel(_ title: LocalizedStringKey, symbol: String) -> some View {
        #if os(iOS)
        Label(title, systemImage: symbol)
            .font(.headline)
            .frame(maxWidth: .infinity, minHeight: 26)
        #else
        Label(title, systemImage: symbol)
            .frame(minWidth: 78)
        #endif
    }
}

struct GenerationOptions: View {
    @Bindable var model: GeneratorModel
    var wide = false
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    var body: some View {
        GeneratorCard(wide: wide, padding: 0) {
            VStack(spacing: 0) {
                switch model.mode {
                case .password: passwordOptions
                case .passphrase: passphraseOptions
                case .username: usernameOptions
                }
            }
        }
    }

    @ViewBuilder
    private var passwordOptions: some View {
        optionRow {
            #if os(macOS)
            HStack(spacing: Spacing.md) {
                Text("长度")
                lengthSlider
                Text(model.passwordOptions.length, format: .number).monospacedDigit()
            }
            #else
            VStack(spacing: Spacing.xs) {
                LabeledContent("长度") { Text(model.passwordOptions.length, format: .number).monospacedDigit() }
                lengthSlider
            }
            .padding(.vertical, Spacing.sm)
            #endif
        }
        characterToggle("大写字母", hint: "A–Z", key: \.useUppercase)
        characterToggle("小写字母", hint: "a–z", key: \.useLowercase)
        characterToggle("数字", hint: "0–9", key: \.useNumbers)
        characterToggle("符号", hint: "!@#$%", key: \.useSpecial)
        optionDivider
        toggle("避开易混淆字符", hint: "l 1 O 0", value: $model.passwordOptions.avoidAmbiguous)
    }

    private var lengthSlider: some View {
        Slider(value: Binding(get: { Double(model.passwordOptions.length) },
                              set: { model.passwordOptions.length = Int($0.rounded()); model.regenerate() }),
               in: 8...64, step: 1)
            .accessibilityLabel("密码长度")
            .accessibilityValue("\(model.passwordOptions.length) 位")
    }

    private func characterToggle(_ title: LocalizedStringKey, hint: String,
                                 key: WritableKeyPath<PasswordGeneratorOptions, Bool>) -> some View {
        let options = model.passwordOptions
        let active = [options.useUppercase, options.useLowercase, options.useNumbers, options.useSpecial]
            .filter { $0 }.count
        return Group {
            optionDivider
            toggle(title, hint: hint, value: $model.passwordOptions[dynamicMember: key])
                .disabled(options[keyPath: key] && active == 1)
        }
    }

    @ViewBuilder
    private var passphraseOptions: some View {
        numberOption("单词数量", value: $model.passphraseOptions.wordCount, range: 3...10)
        optionDivider
        optionRow {
            let picker = Picker("分隔符", selection: $model.passphraseOptions.separator) {
                Text("-").tag("-")
                Text("空格").tag(" ")
                Text(".").tag(".")
                Text("_").tag("_")
            }.labelsHidden()
            #if os(macOS)
            LabeledContent("分隔符") { picker.pickerStyle(.segmented).frame(maxWidth: 220) }
            #else
            if dynamicTypeSize.isAccessibilitySize {
                LabeledContent("分隔符") { picker.pickerStyle(.menu) }
            } else {
                VStack(alignment: .leading, spacing: Spacing.sm) {
                    Text("分隔符")
                    picker.pickerStyle(.segmented)
                }
                .padding(.vertical, Spacing.md)
            }
            #endif
        }
        .onChange(of: model.passphraseOptions.separator) { _, _ in model.regenerate() }
        optionDivider
        toggle("首字母大写", value: $model.passphraseOptions.capitalize)
        optionDivider
        toggle("包含数字", value: $model.passphraseOptions.includeNumber)
    }

    @ViewBuilder
    private var usernameOptions: some View {
        textOption("基础名称", value: $model.usernameBase)
        optionDivider
        textOption("邮箱域名", value: $model.usernameDomain)
        optionDivider
        numberOption("随机后缀", value: $model.usernameSuffixLength, range: 2...10)
    }

    private func textOption(_ title: LocalizedStringKey, value: Binding<String>) -> some View {
        optionRow {
            LabeledContent {
                TextField(title, text: value)
                    .labelsHidden()
                    .multilineTextAlignment(.trailing)
                    .autocorrectionDisabled()
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    .keyboardType(.asciiCapable)
                    #endif
            } label: { Text(title) }
        }
        .onChange(of: value.wrappedValue) { _, _ in model.regenerate() }
    }

    private func numberOption(_ title: LocalizedStringKey, value: Binding<Int>, range: ClosedRange<Int>) -> some View {
        optionRow {
            Stepper(value: value, in: range) {
                LabeledContent(title) { Text(value.wrappedValue, format: .number).monospacedDigit() }
            }
            .accessibilityValue("\(value.wrappedValue)")
        }
        .onChange(of: value.wrappedValue) { _, _ in model.regenerate() }
    }

    private func toggle(_ title: LocalizedStringKey, hint: String? = nil, value: Binding<Bool>) -> some View {
        optionRow {
            Toggle(isOn: value) {
                HStack(spacing: Spacing.sm) {
                    Text(title)
                    if let hint {
                        #if os(macOS)
                        Spacer()
                        #endif
                        Text(hint)
                            .font(.system(.footnote, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .accessibilityHidden(true)
                    }
                }
            }
            #if os(macOS)
            .toggleStyle(.checkbox)
            #endif
        }
        .onChange(of: value.wrappedValue) { _, _ in model.regenerate() }
    }

    private var optionDivider: some View { Divider().padding(.leading, Spacing.lg) }

    private func optionRow<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        content()
            .padding(.horizontal, Spacing.lg)
            #if os(macOS)
            .frame(maxWidth: .infinity, minHeight: 38, alignment: .leading)
            #else
            .frame(maxWidth: .infinity, minHeight: 52, alignment: .leading)
            #endif
    }
}

struct GenerationHistoryList: View {
    let model: GeneratorModel
    let copy: (String) -> Void
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    var body: some View {
        Group {
            if model.history.isEmpty {
                if model.isHistoryBusy {
                    ProgressView()
                } else if model.historyError != nil {
                    ContentUnavailableView {
                        Label("无法读取生成历史", systemImage: "exclamationmark.triangle")
                    } actions: {
                        Button("重试") { Task { await model.prepareHistory() } }
                    }
                } else {
                    ContentUnavailableView("没有生成历史", systemImage: "clock.arrow.circlepath",
                                           description: Text("生成或拷贝的结果会显示在这里。"))
                }
            } else {
                List {
                    if let error = model.historyError {
                        Text(LocalizedStringKey(error)).font(.footnote).foregroundStyle(.secondary)
                    }
                    ForEach(model.history) { entry in
                        let timestamp = Text(.currentDate, format: Date.AnchoredRelativeFormatStyle(anchor: entry.date, presentation: .named))
                        InlineCopyButton(action: { copy(entry.value) }) { copied in
                            HStack(spacing: Spacing.sm) {
                                VStack(alignment: .leading, spacing: Spacing.xs) {
                                    Text(entry.value)
                                        .font(.system(.body, design: .monospaced))
                                        .lineLimit(dynamicTypeSize.isAccessibilitySize ? nil : 1)
                                        .truncationMode(.middle)
                                        .privacySensitive()
                                    HStack(spacing: Spacing.xs) {
                                        Text(LocalizedStringKey(entry.kind.titleKey))
                                        Text("·")
                                        timestamp
                                    }
                                    .font(.footnote).foregroundStyle(.secondary)
                                }
                                Spacer(minLength: Spacing.xs)
                                if copied { InlineCopyIndicator() }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            #if os(iOS)
                            .frame(minHeight: 52)
                            #endif
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(Text("拷贝\(Text(LocalizedStringKey(entry.kind.titleKey)))"))
                        .accessibilityValue(timestamp)
                    }
                }
                #if os(iOS)
                .listStyle(.insetGrouped)
                #else
                .listStyle(.inset)
                #endif
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .task { await model.prepareHistory() }
    }
}
