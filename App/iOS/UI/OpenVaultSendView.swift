import SwiftUI
import UIShared

@available(iOS 27.0, *)
struct OpenVaultSendView: View {
    let vault: VaultService
    var dataRevision: UInt64 = 0

    @State private var showComposer = false

    var body: some View {
        SendWorkspace(service: vault.sendService, showComposer: $showComposer, dataRevision: dataRevision)
    }
}
