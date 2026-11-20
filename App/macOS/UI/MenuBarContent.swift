import SwiftUI
import UIShared
import DesignSystem
import VaultRepository

@available(macOS 27.0, *)
public struct MenuBarContent: View {
    private let auth: AuthService
    private let vault: VaultService
    private let biometricsEnabled: Bool

    @State private var unlockModel: UnlockModel
    @State private var listModel: VaultListModel
    @State private var isUnlocked = false
    @State private var touchIDAvailable = false
    @State private var query = ""
    @State private var copiedMessage: String?
    @State private var toastID = UUID()

    public init(auth: AuthService, vault: VaultService, biometricsEnabled: Bool = false) {
        self.auth = auth
        self.vault = vault
        self.biometricsEnabled = biometricsEnabled
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
        .copyToast(copiedMessage, bottomInset: 14)
        .task { await monitorLockState() }
    }

    private var header: some View {
        HStack(spacing: 10) {
            OpenVaultMark(size: 34)
            VStack(alignment: .leading, spacing: 1) {
                Text("OpenVault")
                    .font(.headline)
                Text(isUnlocked ? "保险库已解锁" : "保险库已锁定")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Image(systemName: isUnlocked ? "lock.open.fill" : "lock.fill")
                .foregroundStyle(isUnlocked ? Color.green : .secondary)
                .accessibilityHidden(true)
        }
    }

    private var lockedContent: some View {
        VStack(alignment: .leading, spacing: 10) {
            SecureField("主密码", text: $unlockModel.password)
                .textFieldStyle(.roundedBorder)
                .textContentType(.password)
                .privacySensitive()
                .onSubmit(unlock)

            if let message = unlockModel.errorMessage {
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
            }

            HStack(spacing: 8) {
                if biometricsEnabled && touchIDAvailable {
                    Button {
                        Task {
                            await unlockModel.unlockWithBiometrics(reason: "使用触控 ID 解锁 OpenVault")
                            await refreshLockState()
                        }
                    } label: {
                        Label("触控 ID", systemImage: "touchid")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                }

                Button(action: unlock) {
                    Text("解锁").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(unlockModel.password.isEmpty)
            }
            .disabled(unlockModel.state == .unlocking)
        }
        .modifier(MacTouchIDAvailability(isAvailable: $touchIDAvailable, enabled: biometricsEnabled))
    }

    private var unlockedContent: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField("搜索保险库", text: $query)
                .textFieldStyle(.roundedBorder)

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
                        ForEach(results, id: \.macStableID) { cipher in
                            MenuResultRow(cipher: cipher) { value, message in
                                MacClipboard.copy(value)
                                showToast(message)
                            }
                        }
                    }
                }
                .frame(maxHeight: 360)
                .background(Palette.contentBackground, in: RoundedRectangle(cornerRadius: CornerRadius.macCard))
            }

            Divider()
            Button {
                Task {
                    await auth.lock()
                    await refreshLockState()
                }
            } label: {
                Label("锁定保险库", systemImage: "lock")
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .buttonStyle(.borderless)
        }
    }

    private func unlock() {
        guard !unlockModel.password.isEmpty, unlockModel.state != .unlocking else { return }
        Task {
            await unlockModel.unlockWithPassword()
            await refreshLockState()
        }
    }

    private func monitorLockState() async {
        await refreshLockState()
        while !Task.isCancelled {
            try? await Task.sleep(for: .milliseconds(500))
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
                listModel.clearDecryptedItems()
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
        copiedMessage = message
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(1.6))
            guard toastID == id else { return }
            copiedMessage = nil
        }
    }
}

@available(macOS 27.0, *)
private struct MenuResultRow: View {
    let cipher: PlaintextCipher
    let onCopy: (String, String) -> Void

    var body: some View {
        HStack(spacing: 9) {
            BrandBadge(cipher.name, diameter: 28)
            VStack(alignment: .leading, spacing: 1) {
                Text(cipher.name.nilIfBlank ?? "未命名条目")
                    .font(.body.weight(.medium))
                    .lineLimit(1)
                if let username = cipher.login?.username?.nilIfBlank {
                    Text(username)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            .privacySensitive()
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
        .padding(.horizontal, 8)
        .frame(minHeight: 42)
    }
}

private extension PlaintextCipher {
    func matchesMenuSearch(_ query: String) -> Bool {
        name.localizedCaseInsensitiveContains(query)
            || login?.username?.localizedCaseInsensitiveContains(query) == true
            || login?.uris.contains { $0.uri.localizedCaseInsensitiveContains(query) } == true
    }
}
