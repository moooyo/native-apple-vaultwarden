import SwiftUI
import DesignSystem
import VaultRepository

struct MacSidebarView: View {
    @Binding var selection: MacDestination
    let counts: MacSidebarCounts
    let folders: [PlaintextFolder]
    let onNewFolder: () -> Void
    let onRenameFolder: (PlaintextFolder) -> Void
    let onDeleteFolder: (PlaintextFolder) -> Void

    var body: some View {
        List(selection: Binding<MacDestination?>(
            get: { selection },
            set: { if let destination = $0 { selection = destination } }
        )) {
            Section {
                row(.all)
                row(.favorites)
                row(.authenticator)
            }
            Section("类型") {
                row(.login)
                row(.card)
                row(.identity)
                row(.secureNote)
                row(.sshKey)
            }
            Section {
                ForEach(folders, id: \.id) { folder in
                    row(.folder(folder.id), title: folder.name)
                        .contextMenu {
                            Button("重命名…") { onRenameFolder(folder) }
                            Button("删除文件夹…", role: .destructive) { onDeleteFolder(folder) }
                        }
                }
                row(.unfiled)
            } header: {
                HStack {
                    Text("文件夹")
                    Spacer()
                    Button("新建文件夹", systemImage: "plus", action: onNewFolder)
                        .labelStyle(.iconOnly)
                        .buttonStyle(.borderless)
                        .help("新建文件夹")
                }
            }
            Section("工具") {
                row(.send)
                row(.generator)
            }
            Section("隐藏的条目") {
                row(.archive)
                row(.trash)
            }
        }
        .listStyle(.sidebar)
        .environment(\.defaultMinListRowHeight, LayoutMetric.desktopSidebarRowHeight)
        .accessibilityLabel("OpenVault 侧栏")
    }

    private func row(_ destination: MacDestination, title: String? = nil) -> some View {
        Label {
            Text(title ?? destination.title).lineLimit(1)
        } icon: {
            if destination == .favorites {
                Image(systemName: destination.systemImage).foregroundStyle(.orange)
            } else {
                Image(systemName: destination.systemImage)
            }
        }
        .badge(counts.value(for: destination).map { Text($0, format: .number) })
        .tag(destination)
    }
}
