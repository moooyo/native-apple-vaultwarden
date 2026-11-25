import SwiftUI
import UIShared
import VaultRepository

extension EnvironmentValues {
    @Entry var deviceApprovalLogin: DeviceApprovalRepository? = nil
}

struct DeviceLoginOption: View {
    let model: LoginModel
    @Environment(\.deviceApprovalLogin) private var repository
    @State private var showing = false

    var body: some View {
        if let repository {
            Button("Log In with Another Device", systemImage: "ipad.and.iphone") { showing = true }
                .disabled(model.isBusy || model.isChallenged || !model.validAddress || !model.serverURL.hasPrefix("https://"))
                .sheet(isPresented: $showing) {
                    DeviceLoginRequestView(repository: repository, email: model.email, serverURL: model.serverURL) {
                        model.acceptDeviceLoginResult($0)
                        showing = false
                    }
                }
        }
    }
}

private struct DeviceLoginRequestView: View {
    let repository: DeviceApprovalRepository
    let email: String
    let serverURL: String
    let onResult: (LoginResult) -> Void
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var phase
    @State private var request: DeviceApprovalRepository.PendingSignIn?
    @State private var job: Task<Void, Never>?
    @State private var feedback: String?
    @State private var handedOff = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Use another device already signed in to this account. Device login on this server requires this installation to have signed in before.")
                    if let request {
                        LabeledContent("Fingerprint", value: request.fingerprint)
                            .privacySensitive().textSelection(.enabled)
                        Text("Compare the full fingerprint on the other device before approving. This request expires in about five minutes.")
                        Button("Check for Approval") { runCheck(request) }.disabled(job != nil)
                    } else {
                        Button("Send Login Request", action: begin).disabled(job != nil)
                    }
                    if job != nil { ProgressView() }
                    if let feedback { Text(feedback).font(.footnote).foregroundStyle(.secondary) }
                }
            }
            .navigationTitle("Log In with Another Device")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { stop(); dismiss() } } }
        }
        #if os(macOS)
        .frame(minWidth: 440, minHeight: 340)
        #endif
        .onChange(of: phase) { _, phase in if phase == .background { stop(); dismiss() } }
        .onDisappear { stop() }
    }

    private func begin() {
        feedback = nil
        job = Task {
            defer { if !Task.isCancelled { job = nil } }
            do {
                let pending = try await repository.begin(email: email, serverURL: serverURL)
                guard !Task.isCancelled else { await repository.cancel(requestID: pending.id); return }
                request = pending
            } catch {
                if !Task.isCancelled {
                    feedback = String(localized: "Device login could not start. Check that this client is a known device, or use your master password.")
                }
            }
        }
    }

    private func runCheck(_ pending: DeviceApprovalRepository.PendingSignIn) {
        feedback = nil
        job = Task {
            defer { if !Task.isCancelled { job = nil } }
            do {
                let result = try await repository.checkApproval(requestID: pending.id)
                guard !Task.isCancelled else { return }
                if let result { handedOff = true; onResult(result) }
                else { feedback = String(localized: "Waiting for approval from the other device.") }
            } catch {
                await repository.cancel(requestID: pending.id)
                if !Task.isCancelled {
                    request = nil
                    feedback = String(localized: "The request expired, was rejected, or could not be verified. Start again or use your master password.")
                }
            }
        }
    }

    private func stop() {
        job?.cancel()
        job = nil
        if !handedOff {
            let requestID = request?.id
            Task { await repository.cancel(requestID: requestID) }
        }
        request = nil
    }
}

struct DeviceApprovalView: View {
    let repository: DeviceApprovalRepository
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var phase
    @State private var lease: AccountSessionLease?
    @State private var approvals: [DeviceApprovalRepository.Approval] = []
    @State private var pending: DeviceApprovalRepository.Approval?
    @State private var matched = false
    @State private var password = ""
    @State private var working = false
    @State private var responseTask: Task<Void, Never>?
    @State private var feedback: String?

    var body: some View {
        NavigationStack {
            Form {
                Button("Refresh Requests", systemImage: "arrow.clockwise") { Task { await load() } }.disabled(working)
                ForEach(approvals) { approval in
                    Button { pending = approval; matched = false; password = "" } label: {
                        LabeledContent(approval.request.requestDeviceType, value: approval.fingerprint)
                    }
                }
                if approvals.isEmpty { Text("No pending requests.").foregroundStyle(.secondary) }
                if let pending {
                    Section {
                        Text(pending.fingerprint).textSelection(.enabled).privacySensitive()
                        LabeledContent("Request IP", value: pending.request.requestIPAddress).privacySensitive()
                        Toggle("The entire fingerprint matches the requesting device", isOn: $matched)
                        SecureField("Master Password", text: $password)
                        Button("Approve Request") { respond(pending, approve: true) }.disabled(!matched || password.isEmpty || working)
                        Button("Deny Request", role: .destructive) { respond(pending, approve: false) }.disabled(password.isEmpty || working)
                        Button("Cancel", role: .cancel) { password = ""; self.pending = nil; matched = false }
                    } header: { Text("Confirm Device Request") }
                }
                if let feedback { Text(feedback).font(.footnote).foregroundStyle(.secondary) }
            }
            .navigationTitle("Device Login Requests")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Done") { clear(); dismiss() } } }
        }
        #if os(macOS)
        .frame(minWidth: 500, minHeight: 400)
        #endif
        .task {
            guard let initial = await repository.unlockedSessionLease() else { dismiss(); return }
            lease = initial
            await load()
            while !Task.isCancelled {
                do { try await Task.sleep(for: .milliseconds(250)) } catch { return }
                guard await repository.unlockedSessionLease() == initial else { clear(); dismiss(); return }
            }
        }
        .onChange(of: phase) { _, phase in if phase == .background { clear(); dismiss() } }
        .onDisappear { clear() }
    }

    private func load() async {
        guard let lease, !working else { return }
        working = true
        defer { working = false }
        do {
            let requests = try await repository.approvalRequests(for: lease)
            guard self.lease == lease, !Task.isCancelled else { return }
            approvals = requests
            feedback = nil
        } catch {
            if self.lease == lease, !Task.isCancelled {
                feedback = String(localized: "Could not load device requests on this server.")
            }
        }
    }

    private func respond(_ request: DeviceApprovalRepository.Approval, approve: Bool) {
        guard let lease, !working else { return }
        working = true
        let submitted = password
        password = ""
        pending = nil
        matched = false
        responseTask = Task {
            do {
                try await repository.respond(to: request, approve: approve, password: submitted)
                guard self.lease == lease, !Task.isCancelled else { return }
                working = false
                await load()
            } catch {
                guard self.lease == lease, !Task.isCancelled else { return }
                working = false
                feedback = String(localized: "The device request could not be confirmed. Refresh before trying again.")
            }
        }
    }

    private func clear() {
        responseTask?.cancel()
        responseTask = nil
        lease = nil
        pending = nil
        matched = false
        password = ""
        approvals = []
    }
}
