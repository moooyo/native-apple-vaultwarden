import SwiftUI
import UIShared

struct RecoveryCodeLoginOption: View {
    let model: LoginModel
    @State private var presented = false
    @State private var code = ""
    @State private var confirmed = false
    @Environment(\.scenePhase) private var phase

    var body: some View {
        if model.canUseRecoveryCode {
            Button("Use a Recovery Code") { presented = true }
                .sheet(isPresented: $presented, onDismiss: clear) {
                    NavigationStack {
                        Form {
                            Section {
                                Text("A recovery code is used once. Using it removes all existing two-step login methods on this server. Set up a new second factor after signing in.")
                                SecureField("Recovery Code", text: $code)
                                    .autocorrectionDisabled()
                                Toggle("I understand this removes my two-step login methods", isOn: $confirmed)
                                Button("Recover Account", role: .destructive) {
                                    let submitted = code
                                    clear()
                                    presented = false
                                    Task { await model.submitRecoveryCode(submitted) }
                                }
                                .disabled(!confirmed || code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || model.isBusy)
                            }
                        }
                        .navigationTitle("Use a Recovery Code")
                        .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { presented = false } } }
                    }
                    #if os(macOS)
                    .frame(minWidth: 440, minHeight: 270)
                    #endif
                }
                .onChange(of: phase) { _, phase in if phase == .background { clear(); presented = false } }
        }
    }

    private func clear() { code = ""; confirmed = false }
}
