import AppKit
import Darwin
import Foundation

/// Best-effort attribution for display only. Approval scope never depends on process ancestry.
struct MacSSHAgentPeer: Equatable, Sendable {
    var pid: pid_t?
    var commandName: String?
    var appName: String?
    var chain: [String] = []

    @MainActor static func read(from descriptor: Int32) -> Self {
        var pid: pid_t = 0
        var size = socklen_t(MemoryLayout.size(ofValue: pid))
        guard getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) == 0, pid > 0 else { return Self() }

        var chain: [String] = []
        var ancestor = pid
        var appName: String?
        var command: String?
        for _ in 0..<12 where ancestor > 1 {
            let app = NSRunningApplication(processIdentifier: ancestor)
            if let app, let url = app.bundleURL, url.pathExtension == "app", let name = app.localizedName {
                appName = MacSSHAgentProtocol.safeLabel(name)
            }
            var info = proc_bsdinfo()
            let length = MemoryLayout.size(ofValue: info)
            guard proc_pidinfo(ancestor, PROC_PIDTBSDINFO, 0, &info, Int32(length)) == length,
                  info.pbi_uid == geteuid() else { break }
            let processName = withUnsafeBytes(of: &info.pbi_name) {
                String(decoding: $0.prefix(while: { $0 != 0 }), as: UTF8.self)
            }
            let shortName = MacSSHAgentProtocol.safeLabel(processName)
            if ancestor == pid { command = shortName.isEmpty ? nil : shortName }
            if let appName { chain.append(appName); break }
            if !shortName.isEmpty { chain.append(shortName) }
            guard info.pbi_ppid != info.pbi_pid else { break }
            ancestor = pid_t(bitPattern: info.pbi_ppid)
        }
        if appName != nil, chain.last != appName, let appName { chain.append(appName) }
        if command == "ssh", chain.count > 1, chain[1] == "git" || chain[1].hasPrefix("git-") {
            command = "git"
            chain.removeFirst()
            chain[0] = "git"
            if chain.count > 1, chain[1] == "git" { chain.remove(at: 1) }
        }
        let displayChain = (chain.prefix(2) + chain.dropFirst(2).suffix(1)).reversed()
        return Self(pid: pid, commandName: command, appName: appName ?? command, chain: Array(displayChain))
    }
}
