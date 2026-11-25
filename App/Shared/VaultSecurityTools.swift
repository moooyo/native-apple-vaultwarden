import SwiftUI
import UIShared
import VaultRepository

struct VaultSecurityTools {
    let localVault: any VaultService
    let twoFactor: AccountTwoFactorManagement
    let emergencyAccess: EmergencyAccessRepository
    let deviceApproval: DeviceApprovalRepository
    let generation: UInt64
}

extension EnvironmentValues {
    @Entry var vaultSecurityTools: VaultSecurityTools? = nil
}

struct VaultSecurityActions: View {
    let auth: any AuthService
    let tools: VaultSecurityTools
    let isUnlocked: Bool
    @State private var page: Page?
    @State private var confirmation: AccountSessionLease?
    @State private var confirming = false
    @State private var working = false
    @State private var result: String?
    @Environment(\.scenePhase) private var phase
    @State private var upgrade: Task<Void, Never>?

    private enum Page: String, Identifiable {
        case health, twoFactor, emergency, deviceApproval
        var id: String { rawValue }
    }

    var body: some View {
        Group {
            Button("Password Health", systemImage: "heart.text.clipboard") { page = .health }
            Button("Two-step Login", systemImage: "shield.lefthalf.filled") { page = .twoFactor }
            Button("Emergency Access", systemImage: "person.badge.shield.checkmark") { page = .emergency }
            Button("Device Login Requests", systemImage: "ipad.and.iphone") { page = .deviceApproval }
            Button("Upgrade Item Encryption Keys", systemImage: "key") {
                Task {
                    guard let lease = await auth.transferSession() else { return }
                    confirmation = lease
                    confirming = true
                }
            }
            .disabled(working)
            if let result { Text(result).font(.footnote).foregroundStyle(.secondary) }
        }
        .disabled(!isUnlocked)
        .sheet(item: $page) { page in
            switch page {
            case .health:
                VaultHealthReportView(auth: auth, vault: tools.localVault, authStateGeneration: tools.generation)
            case .twoFactor:
                AccountTwoFactorView(repository: tools.twoFactor, isUnlocked: isUnlocked)
            case .emergency:
                EmergencyAccessView(repository: tools.emergencyAccess, sessionIsUnlocked: isUnlocked)
            case .deviceApproval:
                DeviceApprovalView(repository: tools.deviceApproval)
            }
        }
        .confirmationDialog("Upgrade item encryption keys?", isPresented: $confirming) {
            Button("Upgrade Items") {
                if let confirmation { startUpgrade(confirmation) }
                confirmation = nil
            }
            Button("Cancel", role: .cancel) { confirmation = nil }
        } message: {
            Text("This updates eligible active personal items on your server. Items with pending changes or data that cannot be preserved are skipped.")
        }
        .onChange(of: isUnlocked) { _, unlocked in if !unlocked { clear() } }
        .onChange(of: tools.generation) { _, _ in clear() }
        .onChange(of: phase) { _, phase in if phase == .background { clear() } }
        .onDisappear { clear() }
    }

    private func startUpgrade(_ lease: AccountSessionLease) {
        guard !working else { return }
        working = true
        result = nil
        upgrade = Task { @MainActor in
            defer { if !Task.isCancelled { working = false; upgrade = nil } }
            do {
                let report = try await tools.localVault.upgradeLegacyCipherKeys(for: lease)
                guard await auth.transferSession() == lease, !Task.isCancelled else { return }
                if report.requiresSync {
                    result = String(localized: "Upgraded \(report.upgraded), skipped \(report.skipped), failed \(report.failed). Sync before trying again; the last write could not be confirmed.")
                } else {
                    result = String(localized: "Upgraded \(report.upgraded), skipped \(report.skipped), failed \(report.failed).")
                }
            } catch {
                guard await auth.transferSession() == lease, !Task.isCancelled else { return }
                result = String(localized: "Could not complete the upgrade. Check the connection and sync before retrying.")
            }
        }
    }

    private func clear() {
        page = nil
        confirmation = nil
        confirming = false
        upgrade?.cancel()
        upgrade = nil
        working = false
        result = nil
    }
}
