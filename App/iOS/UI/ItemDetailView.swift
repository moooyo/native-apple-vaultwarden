import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels
import Generators

@available(iOS 27.0, *)
public struct ItemDetailView: View {
    @State private var model: ItemDetailModel
    private let vault: VaultService
    private let onChanged: () -> Void

    @State private var showingEdit = false
    @State private var toastMessage: String?
    @State private var toastTask: Task<Void, Never>?

    public init(model: ItemDetailModel, vault: VaultService, onChanged: @escaping () -> Void) {
        _model = State(initialValue: model)
        self.vault = vault
        self.onChanged = onChanged
    }

    private var cipher: PlaintextCipher { model.cipher }
    private var supportsEditing: Bool {
        let type = CipherType(rawValue: cipher.type)
        return type == .login || type == .secureNote
    }

    public var body: some View {
        ScrollView {
            LazyVStack(spacing: Spacing.lg) {
                header

                if let login = cipher.login {
                    credentialsCard(login)
                }

                if let login = cipher.login, !login.uris.isEmpty {
                    websitesCard(login.uris)
                }

                if let notes = cipher.notes, !notes.isEmpty {
                    notesCard(notes)
                }

                securityStatusCard
            }
            .padding(.horizontal, Spacing.lg)
            .padding(.vertical, Spacing.sm)
        }
        .background(Palette.groupedBackground)
        .scrollEdgeEffectStyle(.soft, for: .all)
        .navigationTitle(cipher.openVaultName)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if supportsEditing {
                    Button("编辑") { showingEdit = true }
                        .fontWeight(.semibold)
                }
            }
        }
        .sheet(isPresented: $showingEdit) {
            NavigationStack {
                ItemEditView(vault: vault, existing: cipher) { id in
                    showingEdit = false
                    refresh(id: id)
                }
            }
            .presentationDetents([.large])
            .presentationDragIndicator(.visible)
        }
        .copyToast(toastMessage)
        .onDisappear { toastTask?.cancel() }
    }

    private var header: some View {
        VStack(spacing: Spacing.sm) {
            BrandBadge(cipher.openVaultName, diameter: 60)
            Text(cipher.openVaultName)
                .font(.title2.bold())
                .multilineTextAlignment(.center)
            Text(headerSubtitle)
                .font(.subheadline)
                .foregroundStyle(Palette.secondaryText)
                .lineLimit(2)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, Spacing.sm)
    }

    private var headerSubtitle: String {
        if let host = cipher.login?.uris.first.flatMap({ URL(string: $0.uri)?.host }), !host.isEmpty {
            return "\(cipher.openVaultKindLabel) · \(host)"
        }
        return cipher.openVaultKindLabel
    }

    private func credentialsCard(_ login: PlaintextCipher.Login) -> some View {
        OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                if let username = login.username, !username.isEmpty {
                    fieldRow(label: "用户名", value: username) {
                        Clipboard.copy(username)
                        showToast("已拷贝用户名")
                    }
                }

                if login.username?.isEmpty == false, login.password?.isEmpty == false {
                    Divider().padding(.leading, Spacing.lg)
                }

                if let password = login.password, !password.isEmpty {
                    passwordRow(password)
                }

                if (login.username?.isEmpty == false || login.password?.isEmpty == false),
                   model.hasTOTP {
                    Divider().padding(.leading, Spacing.lg)
                }

                if let configuration = model.totpConfiguration {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        totpRow(configuration, at: context.date)
                    }
                }
            }
        }
    }

    private func fieldRow(label: String, value: String, onCopy: @escaping () -> Void) -> some View {
        HStack(spacing: Spacing.md) {
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text(label)
                    .font(Typography.fieldLabel)
                    .foregroundStyle(Palette.secondaryText)
                Text(value)
                    .font(.body)
                    .foregroundStyle(Palette.primaryText)
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: Spacing.sm)
            Button(action: onCopy) { Image(systemName: "doc.on.doc") }
                .buttonStyle(.plain)
                .foregroundStyle(Palette.accent)
                .frame(width: 44, height: 44)
                .accessibilityLabel("复制\(label)")
        }
        .padding(.leading, Spacing.lg)
        .padding(.trailing, Spacing.sm)
        .frame(minHeight: 60)
    }

    private func passwordRow(_ password: String) -> some View {
        HStack(spacing: Spacing.sm) {
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text("密码")
                    .font(Typography.fieldLabel)
                    .foregroundStyle(Palette.secondaryText)
                Text(model.revealPassword
                     ? password
                     : String(repeating: "•", count: min(max(password.count, 8), 18)))
                    .font(.system(size: model.revealPassword ? 14.5 : 16,
                                  design: .monospaced))
                    .foregroundStyle(Palette.primaryText)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .privacySensitive()
            }
            Spacer(minLength: 0)
            Button { model.toggleReveal() } label: {
                Image(systemName: model.revealPassword ? "eye.slash" : "eye")
            }
            .buttonStyle(.plain)
            .foregroundStyle(Palette.accent)
            .frame(width: 40, height: 44)
            .accessibilityLabel(model.revealPassword ? "隐藏密码" : "显示密码")
            Button {
                Clipboard.copy(password)
                showToast("已拷贝密码")
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.plain)
            .foregroundStyle(Palette.accent)
            .frame(width: 40, height: 44)
            .accessibilityLabel("复制密码")
        }
        .padding(.leading, Spacing.lg)
        .padding(.trailing, Spacing.sm)
        .frame(minHeight: 64)
    }

    private func totpRow(_ configuration: TOTPConfiguration, at date: Date) -> some View {
        let raw = TOTP.code(for: configuration, at: date)
        let code = OTPRingMath.formatCode(raw)
        let seconds = TOTP.secondsRemaining(for: configuration, at: date)
        let progress = OTPRingMath.progress(secondsRemaining: seconds, period: configuration.period)

        return HStack(spacing: Spacing.md) {
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text("验证码")
                    .font(Typography.fieldLabel)
                    .foregroundStyle(Palette.secondaryText)
                HStack(spacing: Spacing.md) {
                    Text(code)
                        .font(.system(size: 19, weight: .medium, design: .monospaced))
                        .monospacedDigit()
                        .privacySensitive()
                    CountdownRing(progress: progress, size: 22)
                }
            }
            Spacer()
            Button {
                Clipboard.copy(raw)
                showToast("已拷贝验证码")
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.plain)
            .foregroundStyle(Palette.accent)
            .frame(width: 44, height: 44)
            .accessibilityLabel("复制验证码")
        }
        .padding(.leading, Spacing.lg)
        .padding(.trailing, Spacing.sm)
        .frame(minHeight: 68)
    }

    private func websitesCard(_ uris: [PlaintextCipher.Uri]) -> some View {
        OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                ForEach(Array(uris.enumerated()), id: \.offset) { index, entry in
                    HStack(spacing: Spacing.md) {
                        Text(index == 0 ? "网站" : "网站 \(index + 1)")
                            .foregroundStyle(Palette.primaryText)
                        Spacer()
                        Text(entry.uri)
                            .foregroundStyle(Palette.secondaryText)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Button {
                            Clipboard.copy(entry.uri)
                            showToast("已拷贝网站")
                        } label: {
                            Image(systemName: "doc.on.doc")
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(Palette.accent)
                        .frame(width: 36, height: 44)
                        .accessibilityLabel("复制网站")
                    }
                    .padding(.horizontal, Spacing.lg)
                    .frame(minHeight: 56)

                    if index < uris.count - 1 { Divider().padding(.leading, Spacing.lg) }
                }
            }
        }
    }

    private func notesCard(_ notes: String) -> some View {
        OpenVaultCard {
            VStack(alignment: .leading, spacing: Spacing.sm) {
                Text("备注")
                    .font(Typography.fieldLabel)
                    .foregroundStyle(Palette.secondaryText)
                Text(notes)
                    .font(.body)
                    .foregroundStyle(Palette.primaryText)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private var securityStatusCard: some View {
        OpenVaultCard {
            HStack(spacing: Spacing.md) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.title3)
                    .foregroundStyle(Palette.accent)
                    .frame(width: 34, height: 34)
                    .background(Palette.accent.opacity(0.12), in: Circle())
                VStack(alignment: .leading, spacing: Spacing.xxs) {
                    Text("安全状态")
                        .font(.headline)
                    Text("此版本尚未接入泄露检测，不对该密码作风险结论。")
                        .font(.caption)
                        .foregroundStyle(Palette.secondaryText)
                }
            }
        }
    }

    private func refresh(id: String) {
        Task {
            if let refreshed = try? await vault.cipher(id: id) {
                model = ItemDetailModel(cipher: refreshed)
            }
            onChanged()
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
