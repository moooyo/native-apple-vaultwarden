import Accessibility
import AppKit
import DesignSystem
import Generators
import SwiftUI
import UIShared
import VaultRepository

struct MenuBarContent: View {
    private let session: MacWindowSession
    private let dataRevision: UInt64
    private var auth: AuthService { session.environment.auth }
    private var vault: VaultService { session.environment.vault }
    private var biometricsEnabled: Bool { session.environment.settings.biometricUnlockEnabled }
    private var isUnlocked: Bool { session.phase == .main }

    @Environment(\.openWindow) private var openWindow
    @State private var unlockModel: UnlockModel
    @State private var items: [PlaintextCipher] = []
    @State private var recentIDs: [String] = []
    @State private var selectedID: String?
    @State private var loaded = false
    @State private var panelVisible = false
    @State private var touchIDAvailable = false
    @State private var query = ""
    @State private var receipt: MenuCopyReceipt?
    @State private var notice: String?
    @State private var loadToken = UUID()

    init(session: MacWindowSession, dataRevision: UInt64) {
        self.session = session
        self.dataRevision = dataRevision
        _unlockModel = State(initialValue: UnlockModel(auth: session.environment.auth))
    }

    private var searchTerm: String { query.trimmingCharacters(in: .whitespacesAndNewlines) }
    private var recentItems: [PlaintextCipher] { recentIDs.compactMap { id in items.first { $0.id == id } } }
    private var results: [PlaintextCipher] {
        guard !searchTerm.isEmpty else { return recentItems }
        return items.filter { cipher in
            cipher.name.localizedStandardContains(searchTerm) || cipher.login?.username?.localizedStandardContains(searchTerm) == true
                || cipher.login?.uris.contains { $0.uri.localizedStandardContains(searchTerm) } == true
        }
        .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                OpenVaultMark(size: 24)
                Text("OpenVault").font(.headline)
                Spacer()
                Circle().fill(isUnlocked ? Color.green : .secondary).frame(width: 6, height: 6).accessibilityHidden(true)
                Text(isUnlocked ? "已解锁" : "已锁定").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            }.padding(.horizontal, 4)
            if isUnlocked { unlockedContent }
            else if session.phase == .unlock { lockedContent }
            else { openVaultButton }
        }
        .padding(12).frame(width: 380)
        .onAppear { panelVisible = true }
        .task(id: session.phase) {
            if isUnlocked { await reload() } else { clearContent() }
        }
        .onChange(of: dataRevision) { if isUnlocked { Task { await reload() } } }
        .task(id: receipt?.token) {
            guard receipt != nil else { return }
            do { try await Task.sleep(for: .milliseconds(1600)) } catch { return }
            receipt = nil
        }
        .onDisappear { panelVisible = false; clearContent() }
    }

    private var unlockedContent: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 7) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary).accessibilityHidden(true)
                TextField("搜索保险库", text: $query).textFieldStyle(.plain)
                if !query.isEmpty {
                    Button("清除搜索", systemImage: "xmark.circle.fill") { query = "" }
                        .labelStyle(.iconOnly).buttonStyle(.borderless).help("清除搜索")
                }
            }
            .padding(.horizontal, 10).frame(height: 32).background(Palette.controlFill, in: Capsule())

            Text(searchTerm.isEmpty ? "最近使用" : "搜索结果")
                .font(.caption.weight(.semibold)).foregroundStyle(.secondary).padding(.horizontal, 6).padding(.top, 4)
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 1) {
                    if !loaded { ProgressView().frame(maxWidth: .infinity).padding(16) }
                    else if results.isEmpty {
                        Text(searchTerm.isEmpty ? "没有最近使用的条目" : "没有匹配的条目")
                            .foregroundStyle(.secondary).frame(maxWidth: .infinity).padding(16)
                    } else {
                        ForEach(results, id: \.macStableID) { cipher in
                            MenuResultRow(cipher: cipher, selected: selectedID == cipher.id,
                                          copied: receipt?.id == cipher.id ? receipt?.field : nil,
                                          select: { selectedID = cipher.id }, copy: { field in copy(field, from: cipher) })
                        }
                    }
                }
            }.frame(height: 310)
            if let notice { Text(notice).font(.caption).foregroundStyle(.secondary) }
            Divider()
            Button(action: generatePassword) {
                menuLabel(receipt?.field == .generated ? "已生成并拷贝" : "生成并拷贝密码", "wand.and.stars", shortcut: "⌥⌘G")
            }.buttonStyle(.plain).keyboardShortcut("g", modifiers: [.option, .command])
            openVaultButton
            Button(action: lock) { menuLabel("锁定保险库", "lock", shortcut: "⇧⌘L") }
                .buttonStyle(.plain).keyboardShortcut("l", modifiers: [.shift, .command])
        }
        .onChange(of: query) { _, _ in selectedID = nil }
    }

    private var lockedContent: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let message = unlockModel.errorMessage {
                Label(message, systemImage: "exclamationmark.triangle").font(.callout)
            }
            HStack {
                SecureField("主密码", text: $unlockModel.password).textContentType(.password).privacySensitive().onSubmit(unlock)
                Button("解锁", action: unlock).disabled(unlockModel.password.isEmpty)
            }
            if biometricsEnabled && touchIDAvailable {
                Button("使用触控 ID 解锁", systemImage: "touchid") {
                    Task {
                        await unlockModel.unlockWithBiometrics(reason: "使用触控 ID 解锁 OpenVault")
                        await session.refresh()
                    }
                }.buttonStyle(.borderedProminent)
            }
            Divider()
            openVaultButton
        }
        .disabled(unlockModel.state == .unlocking)
        .modifier(MacTouchIDAvailability(isAvailable: $touchIDAvailable, enabled: biometricsEnabled))
    }

    private var openVaultButton: some View {
        Button {
            openWindow(id: "vault", value: MacVaultWindowID.workspace)
            NSApp.activate(ignoringOtherApps: true)
        } label: { menuLabel("打开 OpenVault", "macwindow") }
        .buttonStyle(.plain)
    }

    private func menuLabel(_ title: String, _ symbol: String, shortcut: String? = nil) -> some View {
        HStack(spacing: 8) {
            Image(systemName: symbol).foregroundStyle(.tint).frame(width: 18).accessibilityHidden(true)
            Text(title)
            Spacer()
            if let shortcut { Text(shortcut).font(.caption).foregroundStyle(.secondary).accessibilityHidden(true) }
        }.padding(.horizontal, 6).frame(minHeight: 28).contentShape(Rectangle())
    }

    private func lock() {
        clearContent()
        Task { await session.lock() }
    }

    private func unlock() {
        guard !unlockModel.password.isEmpty, unlockModel.state != .unlocking else { return }
        Task {
            await unlockModel.unlockWithPassword()
            await session.refresh()
        }
    }

    private func reload() async {
        let token = UUID()
        loadToken = token
        do {
            let updated = try await vault.ciphers()
            let recent = (try? await vault.recentItemIDs(limit: 8)) ?? []
            guard !Task.isCancelled, loadToken == token, panelVisible, isUnlocked else { return }
            items = updated; recentIDs = recent; loaded = true; notice = nil
            if !items.contains(where: { $0.id == selectedID }) { selectedID = nil }
        } catch {
            guard !Task.isCancelled, loadToken == token else { return }
            items = []; recentIDs = []; loaded = true; notice = "无法载入保险库，请重新打开面板。"
        }
    }

    private func clearContent() {
        loadToken = UUID(); items = []; recentIDs = []; selectedID = nil; query = ""; notice = nil; receipt = nil; loaded = false
        unlockModel = UnlockModel(auth: auth)
    }

    private func generatePassword() {
        Task {
            let token = loadToken
            guard isUnlocked, panelVisible, await auth.isUnlocked() else { return }
            do {
                let password = try PasswordGenerator.generate(.init(length: 20, useSpecial: true))
                if let service = vault as? any GeneratorHistoryService {
                    let session = try await service.generatorHistory().session
                    guard panelVisible, isUnlocked, loadToken == token else { return }
                    try await service.addGeneration(.init(kind: .password, value: password), session: session)
                }
                guard panelVisible, isUnlocked, loadToken == token, await auth.isUnlocked() else { return }
                MacClipboard.copy(password)
                acknowledge(.generated, id: nil)
            } catch { notice = "无法生成密码，请重试。" }
        }
    }

    private func copy(_ field: MenuCopyField, from cipher: PlaintextCipher) {
        guard let id = cipher.id, isUnlocked else { return }
        Task {
            do {
                let current = try await vault.cipher(id: id)
                guard current.deletedDate == nil, current.archivedDate == nil, let value = field.value(in: current),
                      isUnlocked, await auth.isUnlocked() else { await reload(); return }
                MacClipboard.copy(value)
                acknowledge(field, id: id)
                await vault.recordUse(id: id)
                guard isUnlocked else { return }
                recentIDs.removeAll { $0 == id }; recentIDs.insert(id, at: 0)
                recentIDs = Array(recentIDs.prefix(8))
            } catch { notice = "无法拷贝条目，请重新打开保险库。" }
        }
    }

    private func acknowledge(_ field: MenuCopyField, id: String?) {
        notice = nil
        receipt = MenuCopyReceipt(id: id, field: field)
        AccessibilityNotification.Announcement("已拷贝").post()
    }
}

private struct MenuCopyReceipt { let id: String?; let field: MenuCopyField; let token = UUID() }

private enum MenuCopyField {
    case username, password, code, generated

    func value(in cipher: PlaintextCipher) -> String? {
        switch self {
        case .username: return cipher.login?.username.flatMap { $0.isEmpty ? nil : $0 }
        case .password: return cipher.login?.password.flatMap { $0.isEmpty ? nil : $0 }
        case .code:
            guard let secret = cipher.login?.totp, let config = try? TOTP.configuration(from: secret) else { return nil }
            return TOTP.code(for: config, at: .now)
        case .generated: return nil
        }
    }
}

private struct MenuResultRow: View {
    let cipher: PlaintextCipher
    let selected: Bool
    let copied: MenuCopyField?
    let select: () -> Void
    let copy: (MenuCopyField) -> Void

    var body: some View {
        HStack(spacing: 6) {
            Button(action: select) {
                HStack(spacing: 8) {
                    BrandBadge(cipher.name, diameter: 28)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(cipher.name.nilIfBlank ?? "未命名条目").font(.body.weight(.semibold))
                        Text(cipher.macSubtitle ?? cipher.macTypeLabel).font(.caption).foregroundStyle(.secondary)
                    }.lineLimit(1).privacySensitive()
                    Spacer(minLength: 0)
                }.frame(minHeight: 46).contentShape(Rectangle())
            }.buttonStyle(.plain).accessibilityAddTraits(selected ? .isSelected : [])
            if selected {
                if cipher.login?.username?.isEmpty == false { action(.username, "拷贝用户名", "person") }
                if cipher.login?.password?.isEmpty == false { action(.password, "拷贝密码", "key") }
                if let secret = cipher.login?.totp, (try? TOTP.configuration(from: secret)) != nil { action(.code, "拷贝验证码", "number") }
            }
        }
        .padding(.horizontal, 6)
        .background(selected ? Palette.controlFill : Color.clear, in: RoundedRectangle(cornerRadius: 10))
    }

    private func action(_ field: MenuCopyField, _ title: String, _ symbol: String) -> some View {
        Button { copy(field) } label: {
            Image(systemName: copied == field ? "checkmark" : symbol).frame(width: 24, height: 24)
        }
        .buttonStyle(.bordered).controlSize(.small).help(title)
        .accessibilityLabel(title).accessibilityValue(copied == field ? "已拷贝" : "")
    }
}
