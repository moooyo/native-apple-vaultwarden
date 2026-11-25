import SwiftUI
import UIShared
import VaultRepository

struct VaultHealthReportView: View {
    let auth: any AuthService
    let vault: any VaultService
    let authStateGeneration: UInt64

    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @State private var initialAuthStateGeneration: UInt64
    @State private var presentation = Presentation.loading

    private enum Presentation {
        case loading, ready(VaultHealthReport), failed, closed
    }

    init(auth: any AuthService, vault: any VaultService, authStateGeneration: UInt64) {
        self.auth = auth
        self.vault = vault
        self.authStateGeneration = authStateGeneration
        _initialAuthStateGeneration = State(initialValue: authStateGeneration)
    }

    var body: some View {
        platformContent
            .privacySensitive()
            .task(id: isPresenting) {
                guard isPresenting else { return }
                await presentReport()
            }
            .onChange(of: authStateGeneration) { _, _ in close() }
            .onChange(of: scenePhase, initial: true) { _, phase in
                if phase == .background { close() }
            }
            .onDisappear { presentation = .closed }
    }

    @ViewBuilder private var platformContent: some View {
        #if os(macOS)
        VStack(alignment: .leading, spacing: 12) {
            Text("Password Health Report")
                .font(.headline)
                .accessibilityAddTraits(.isHeader)
                .padding(.horizontal, 24)
                .padding(.top, 20)
            reportForm.scrollContentBackground(.hidden)
            HStack {
                Spacer()
                Button("Close", action: close).keyboardShortcut(.cancelAction)
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 20)
        }
        .frame(width: 540, height: 480)
        #else
        reportForm
            .navigationTitle("Password Health Report")
            .navigationBarTitleDisplayMode(.inline)
        #endif
    }

    private var reportForm: some View {
        Form {
            if isPresenting {
                Section {
                    Text("Checks active personal logins with saved passwords on this device. Organization, archived, and trashed items are excluded. This check looks for common signs of weakness and reuse, not data breaches.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                switch presentation {
                case .loading:
                    Section { ProgressView("Checking Passwords…") }
                case .ready(let report):
                    results(report)
                case .failed:
                    Section { Label("Could Not Read the Local Vault", systemImage: "exclamationmark.triangle") }
                case .closed:
                    EmptyView()
                }
            }
        }
        .formStyle(.grouped)
    }

    @ViewBuilder private func results(_ report: VaultHealthReport) -> some View {
        if report.checkedCount == 0 {
            Section { Text("No active personal logins with a readable password.") }
        } else {
            Section("Summary") {
                LabeledContent("Checked logins", value: report.checkedCount.formatted())
                LabeledContent("Logins with weak passwords", value: report.weakCount.formatted())
                LabeledContent("Logins with reused passwords", value: report.reusedCount.formatted())
            }
            if report.findings.isEmpty {
                Section { Text("No weak or reused passwords found by this check.") }
            } else {
                Section("Logins to Review") {
                    ForEach(report.findings) { finding in
                        VStack(alignment: .leading, spacing: 4) {
                            if finding.name.isEmpty { Text("Untitled Login").font(.headline) }
                            else { Text(verbatim: finding.name).font(.headline) }
                            ForEach(finding.weaknesses.indices, id: \.self) { index in
                                Text(reason(finding.weaknesses[index]))
                                    .font(.callout)
                                    .foregroundStyle(.secondary)
                            }
                            if finding.reuseCount > 1 {
                                Text("Same password used by \(finding.reuseCount) logins.")
                                    .font(.callout)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .accessibilityElement(children: .combine)
                    }
                }
            }
        }
    }

    private func reason(_ weakness: VaultHealthReport.Weakness) -> LocalizedStringKey {
        switch weakness {
        case .tooShort: "Fewer than 12 characters."
        case .limitedCharacterVariety: "Fewer than four distinct characters, ignoring case."
        case .commonPattern: "Contains a common password pattern."
        case .repeatedPattern: "Repeats the same short pattern."
        }
    }

    private var isPresenting: Bool {
        if case .closed = presentation { return false }
        return authStateGeneration == initialAuthStateGeneration && scenePhase != .background
    }

    private func presentReport() async {
        defer { close() }
        let current = await auth.transferSession()
        guard !Task.isCancelled, isPresenting, let lease = current else { return }

        // Keep checking during the scan and after publication. The generation change also
        // hides content immediately when the parent observes a lock or account transition.
        async let watcher: Void = watchSession(lease)
        do {
            let report = try await VaultHealthReport.load(auth: auth, vault: vault, for: lease)
            await publish(.ready(report), for: lease)
        } catch is CancellationError {
            return
        } catch {
            await publish(.failed, for: lease)
        }
        await watcher
    }

    private func publish(_ next: Presentation, for lease: AccountSessionLease) async {
        let current = await auth.transferSession()
        guard !Task.isCancelled, isPresenting else { return }
        guard current == lease else { close(); return }
        presentation = next
    }

    private func watchSession(_ lease: AccountSessionLease) async {
        while await verifySession(lease) {
            do { try await Task.sleep(for: .milliseconds(500)) }
            catch { return }
        }
    }

    private func verifySession(_ lease: AccountSessionLease) async -> Bool {
        guard !Task.isCancelled, isPresenting else { return false }
        let current = await auth.transferSession()
        guard !Task.isCancelled, isPresenting else { return false }
        guard current == lease else { close(); return false }
        return true
    }

    private func close() {
        if case .closed = presentation { return }
        presentation = .closed
        dismiss()
    }
}
