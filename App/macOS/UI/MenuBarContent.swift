import SwiftUI
import UIShared
import DesignSystem
import VaultRepository

@available(macOS 27.0, *)
public struct MenuBarContent: View {
    private let auth: AuthService
    private let vault: VaultService

    @State private var unlockModel: UnlockModel
    @State private var listModel: VaultListModel
    @State private var isUnlocked = false
    @State private var query = ""
    @State private var copiedMessage: String?
    @State private var toastID = UUID()

    public init(auth: AuthService, vault: VaultService) {
        self.auth = auth
        self.vault = vault
        _unlockModel = State(initialValue: UnlockModel(auth: auth))
        _listModel = State(initialValue: VaultListModel(vault: vault))
    }

    private var results: [PlaintextCipher] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        let source = trimmed.isEmpty ? listModel.items : listModel.items.filter { $0.matchesMenuSearch(trimmed) }
        return Array(source.prefix(8))
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            if isUnlocked { unlockedContent } else { lockedContent }
        }
        .padding(14)
        .frame(width: 350)
        .background(MacOpenVaultStyle.detail)
        .overlay(alignment: .bottom) {
            if let copiedMessage {
                GlassToast(copiedMessage)
                    .padding(.bottom, 14)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .task { await monitorLockState() }
    }

    private var header: some View {
        HStack(spacing: 10) {
            OpenVaultMark(size: 34)
            VStack(alignment: .leading, spacing: 1) {
                Text("OpenVault")
                    .font(.system(size: 14, weight: .bold))
                    .foregroundStyle(.white.opacity(0.94))
                Text(isUnlocked ? "保险库已解锁" : "保险库已锁定")
                    .font(.system(size: 10.5))
                    .foregroundStyle(.white.opacity(0.44))
            }
            Spacer()
            Image(systemName: isUnlocked ? "lock.open.fill" : "lock.fill")
                .foregroundStyle(isUnlocked ? Color.green : .white.opacity(0.48))
        }
    }

    private var lockedContent: some View {
        VStack(alignment: .leading, spacing: 10) {
            OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 12) {
                SecureField("主密码", text: $unlockModel.password)
                    .textFieldStyle(.plain)
                    .textContentType(.password)
                    .onSubmit(unlock)
            }
            .overlay {
                RoundedRectangle(cornerRadius: CornerRadius.macCard, style: .continuous)
                    .stroke(.white.opacity(0.08), lineWidth: 0.5)
            }

            if let message = unlockModel.errorMessage {
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Color.orange)
            }

            HStack(spacing: 8) {
                Button {
                    Task {
                        await unlockModel.unlockWithBiometrics(reason: "使用触控 ID 解锁 OpenVault")
                        await refreshLockState()
                    }
                } label: {
                    Label("触控 ID", systemImage: "touchid")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glass)

                Button(action: unlock) {
                    Text("解锁").frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .disabled(unlockModel.password.isEmpty)
            }
        }
    }

    private var unlockedContent: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 7) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.white.opacity(0.42))
                TextField("搜索保险库", text: $query)
                    .textFieldStyle(.plain)
            }
            .padding(.horizontal, 10)
            .frame(height: 30)
            .background(.white.opacity(0.07), in: Capsule())
            .overlay { Capsule().stroke(.white.opacity(0.08), lineWidth: 0.5) }

            if listModel.isLoading && listModel.items.isEmpty {
                ProgressView("正在载入…")
                    .controlSize(.small)
                    .frame(maxWidth: .infinity, minHeight: 90)
            } else if let error = listModel.errorMessage, listModel.items.isEmpty {
                ContentUnavailableView("无法载入保险库", systemImage: "exclamationmark.triangle",
                                       description: Text(error))
                    .frame(maxWidth: .infinity, minHeight: 110)
            } else if results.isEmpty {
                ContentUnavailableView("没有匹配项", systemImage: "magnifyingglass")
                    .frame(maxWidth: .infinity, minHeight: 110)
            } else {
                ScrollView {
                    LazyVStack(spacing: 2) {
                        ForEach(results, id: \.id) { cipher in
                            MenuResultRow(cipher: cipher) { value, message in
                                MacClipboard.copy(value)
                                showToast(message)
                            }
                        }
                    }
                }
                .frame(maxHeight: 360)
            }

            Divider().overlay(.white.opacity(0.08))
            Button {
                Task {
                    await auth.lock()
                    await refreshLockState()
                }
            } label: {
                Label("锁定保险库", systemImage: "lock")
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .buttonStyle(.plain)
            .foregroundStyle(.white.opacity(0.78))
        }
    }

    private func unlock() {
        Task {
            await unlockModel.unlockWithPassword()
            await refreshLockState()
        }
    }

    private func monitorLockState() async {
        await refreshLockState()
        while !Task.isCancelled {
            try? await Task.sleep(for: .seconds(1))
            await refreshLockState()
        }
    }

    private func refreshLockState() async {
        let newValue = await auth.isUnlocked()
        if newValue != isUnlocked {
            isUnlocked = newValue
            query = ""
            if newValue {
                await listModel.load()
            } else {
                // Release decrypted strings as soon as another scene locks the vault.
                listModel = VaultListModel(vault: vault)
                unlockModel = UnlockModel(auth: auth)
            }
        } else if newValue, listModel.items.isEmpty, !listModel.isLoading,
                  listModel.errorMessage == nil {
            await listModel.load()
        }
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
private struct MenuResultRow: View {
    let cipher: PlaintextCipher
    let onCopy: (String, String) -> Void

    @State private var isHovering = false

    var body: some View {
        HStack(spacing: 9) {
            BrandBadge(cipher.name, diameter: 28)
            VStack(alignment: .leading, spacing: 1) {
                Text(cipher.name.nilIfBlank ?? "未命名条目")
                    .font(.system(size: 12.5, weight: .semibold))
                    .lineLimit(1)
                if let username = cipher.login?.username?.nilIfBlank {
                    Text(username)
                        .font(.system(size: 10.5))
                        .foregroundStyle(.white.opacity(0.44))
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 4)
            if let username = cipher.login?.username?.nilIfBlank {
                Button { onCopy(username, "已拷贝用户名") } label: {
                    Image(systemName: "person")
                }
                .buttonStyle(.borderless)
                .help("拷贝用户名")
                .accessibilityLabel("拷贝用户名")
            }
            if let password = cipher.login?.password?.nilIfBlank {
                Button { onCopy(password, "已拷贝密码") } label: {
                    Image(systemName: "key")
                }
                .buttonStyle(.borderless)
                .help("拷贝密码")
                .accessibilityLabel("拷贝密码")
            }
        }
        .foregroundStyle(.white.opacity(0.90))
        .padding(.horizontal, 8)
        .frame(minHeight: 42)
        .background(isHovering ? .white.opacity(0.06) : .clear,
                    in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .onHover { isHovering = $0 }
    }
}

private extension PlaintextCipher {
    func matchesMenuSearch(_ query: String) -> Bool {
        name.localizedCaseInsensitiveContains(query)
            || login?.username?.localizedCaseInsensitiveContains(query) == true
            || login?.uris.contains { $0.uri.localizedCaseInsensitiveContains(query) } == true
    }
}
