// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// GeneratorView — password / passphrase generator. A segmented mode toggle, the
// per-mode options, the generated value (on the opaque content layer, with a strength
// meter), and regenerate / copy actions. Backed by `GeneratorModel` from UIShared.

import SwiftUI
import UIShared
import DesignSystem
import Generators

@available(iOS 26.0, *)
public struct GeneratorView: View {
    @State private var model: GeneratorModel

    /// The App target injects the production EFF word list; default empty keeps this
    /// previewable (passphrase mode then surfaces a clear "list missing" error).
    public init(model: GeneratorModel = GeneratorModel()) {
        _model = State(initialValue: model)
    }

    public var body: some View {
        Form {
            Section {
                generatedDisplay
            }

            Section {
                Picker("Type", selection: $model.mode) {
                    Text("Password").tag(GeneratorModel.Mode.password)
                    Text("Passphrase").tag(GeneratorModel.Mode.passphrase)
                }
                .pickerStyle(.segmented)
            }

            switch model.mode {
            case .password:
                passwordOptions
            case .passphrase:
                passphraseOptions
            }

            if let errorMessage = model.errorMessage {
                Section {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(Palette.warning)
                        .font(Typography.rowSubtitle)
                }
            }
        }
        .navigationTitle("Generator")
        .onAppear { if model.generated.isEmpty { model.regenerate() } }
    }

    // MARK: - Generated value

    private var generatedDisplay: some View {
        VStack(spacing: Spacing.md) {
            Text(model.generated.isEmpty ? "—" : model.generated)
                .font(Typography.secretValue)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .lineLimit(2)
                .padding(Spacing.md)
                .background {
                    // Generated value on the opaque content layer (not glass).
                    RoundedRectangle(cornerRadius: CornerRadius.md, style: .continuous)
                        .fill(Palette.contentBackground)
                }

            if model.mode == .password {
                StrengthMeter(length: model.passwordOptions.length, value: model.generated)
            }

            HStack(spacing: Spacing.md) {
                Button {
                    if let value = model.copyGenerated() { Clipboard.copy(value) }
                } label: {
                    Label("Copy", systemImage: "doc.on.doc").frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .disabled(model.generated.isEmpty)

                Button {
                    model.regenerate()
                } label: {
                    Label("Regenerate", systemImage: "arrow.clockwise").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .listRowInsets(EdgeInsets(top: Spacing.md, leading: Spacing.lg,
                                  bottom: Spacing.md, trailing: Spacing.lg))
        .listRowBackground(Color.clear)
    }

    // MARK: - Password options

    private var passwordOptions: some View {
        Section("Options") {
            Stepper(value: $model.passwordOptions.length, in: 5...128) {
                LabeledContent("Length", value: "\(model.passwordOptions.length)")
            }
            .onChange(of: model.passwordOptions.length) { _, _ in model.regenerate() }

            toggle("A–Z", $model.passwordOptions.useUppercase)
            toggle("a–z", $model.passwordOptions.useLowercase)
            toggle("0–9", $model.passwordOptions.useNumbers)
            toggle("!@#$%^&*", $model.passwordOptions.useSpecial)
            toggle("Avoid ambiguous characters", $model.passwordOptions.avoidAmbiguous)
        }
    }

    // MARK: - Passphrase options

    private var passphraseOptions: some View {
        Section("Options") {
            Stepper(value: $model.passphraseOptions.wordCount, in: 3...12) {
                LabeledContent("Words", value: "\(model.passphraseOptions.wordCount)")
            }
            .onChange(of: model.passphraseOptions.wordCount) { _, _ in model.regenerate() }

            TextField("Separator", text: $model.passphraseOptions.separator)
                .onChange(of: model.passphraseOptions.separator) { _, _ in model.regenerate() }

            toggle("Capitalize", $model.passphraseOptions.capitalize)
            toggle("Include number", $model.passphraseOptions.includeNumber)
        }
    }

    private func toggle(_ title: String, _ binding: Binding<Bool>) -> some View {
        Toggle(title, isOn: binding)
            .onChange(of: binding.wrappedValue) { _, _ in model.regenerate() }
    }
}

// MARK: - Strength meter

@available(iOS 26.0, *)
private struct StrengthMeter: View {
    let length: Int
    let value: String

    /// A rough length-based normalized score in [0, 1]. (zxcvbn-grade scoring is M2.)
    private var strength: PasswordStrength {
        let score = min(Double(value.count) / 20.0, 1.0)
        return PasswordStrength.level(forNormalizedScore: score)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.xs) {
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    Capsule().fill(Palette.separator)
                    Capsule()
                        .fill(strength.color)
                        .frame(width: geo.size.width * strength.fillFraction)
                }
            }
            .frame(height: 6)

            Text(strength.label)
                .font(Typography.caption)
                .foregroundStyle(strength.color)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Password strength")
        .accessibilityValue(strength.label)
    }
}
