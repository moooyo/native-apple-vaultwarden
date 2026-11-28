import AppKit
import Darwin
import Foundation
import Security

struct MacSSHAgentPeer: Equatable, Sendable {
    struct SigningIdentity: Hashable, Sendable {
        let signer: String
        let identifier: String
    }

    struct SocketOwner: Equatable, Sendable {
        let pid: pid_t
        let auditToken: Data
        let executableUUID: Data

        init?(_ descriptor: Int32) {
            var token = audit_token_t()
            var length = socklen_t(MemoryLayout.size(ofValue: token))
            guard getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) == 0,
                  length == MemoryLayout.size(ofValue: token), token.val.5 > 1, token.val.7 > 0 else { return nil }
            var uuid = Data(count: 16)
            length = socklen_t(uuid.count)
            let status = uuid.withUnsafeMutableBytes { getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERUUID, $0.baseAddress, &length) }
            guard status == 0, length == uuid.count, uuid.contains(where: { $0 != 0 }) else { return nil }
            pid = pid_t(bitPattern: token.val.5)
            auditToken = withUnsafeBytes(of: token) { Data($0) }
            executableUUID = uuid
        }

        var matchesLiveExecutable: Bool {
            var usage = rusage_info_v0()
            let status = withUnsafeMutablePointer(to: &usage) {
                $0.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { proc_pid_rusage(pid, RUSAGE_INFO_V0, $0) }
            }
            return status == 0 && withUnsafeBytes(of: usage.ri_uuid) { $0.elementsEqual(executableUUID) }
        }
    }

    let pid: pid_t?
    let commandName: String?
    let appName: String?
    let chain: [String]
    let signingIdentity: SigningIdentity?

    init(pid: pid_t? = nil, commandName: String? = nil, appName: String? = nil, chain: [String] = [],
         signingIdentity: SigningIdentity? = nil) {
        self.pid = pid
        self.commandName = commandName
        self.appName = appName
        self.chain = chain
        self.signingIdentity = signingIdentity
    }

    @MainActor static func read(from descriptor: Int32, initialOwner: SocketOwner?) -> Self {
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
        let signer = initialOwner.flatMap { owner -> SigningIdentity? in
            guard owner.pid == pid, SocketOwner(descriptor) == owner, owner.matchesLiveExecutable else { return nil }
            return directAppSigningIdentity(owner: owner)
        }
        return Self(pid: pid, commandName: command, appName: appName ?? command,
                    chain: Array(displayChain), signingIdentity: signer)
    }

    private static func directAppSigningIdentity(owner: SocketOwner) -> SigningIdentity? {
        // Unix sockets cannot prove which app launched a CLI child. Never let a common
        // signed helper (e.g. /usr/bin/ssh), its ancestry or an ad-hoc signer reuse consent.
        guard let app = NSRunningApplication(processIdentifier: owner.pid), let bundleURL = app.bundleURL,
              bundleURL.pathExtension == "app", let mainExecutable = app.executableURL else { return nil }
        var token = owner.auditToken.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) }
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let size = path.withUnsafeMutableBytes { proc_pidpath_audittoken(&token, $0.baseAddress, UInt32($0.count)) }
        guard size > 0, let executable = path.withUnsafeBufferPointer({ String(validatingCString: $0.baseAddress!) }),
              URL(fileURLWithPath: executable).resolvingSymlinksInPath() == mainExecutable.resolvingSymlinksInPath() else { return nil }

        var guest: SecCode?
        let attributes = [kSecGuestAttributeAudit as String: owner.auditToken] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess, let guest else { return nil }
        var staticCode: SecStaticCode?
        var info: CFDictionary?
        guard SecCodeCopyStaticCode(guest, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let details = info as? [String: Any],
              let identifier = details[kSecCodeInfoIdentifier as String] as? String, identifier == app.bundleIdentifier,
              (1...255).contains(identifier.utf8.count), identifier.utf8.allSatisfy({ byte in
                  switch byte {
                  case 45, 46, 48...57, 65...90, 95, 97...122: true
                  default: false
                  }
              }) else { return nil }

        let team = details[kSecCodeInfoTeamIdentifier as String] as? String
        let requirementText: String
        let signer: String
        if let team, team.utf8.count == 10, team.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) }) {
            requirementText = "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
            signer = team
        } else {
            requirementText = "anchor apple"
            signer = "Apple"
        }
        var requirement: SecRequirement?
        let signedAppRequirement = "\(requirementText) and identifier \"\(identifier)\""
        guard SecRequirementCreateWithString(signedAppRequirement as CFString, [], &requirement) == errSecSuccess, let requirement,
              SecCodeCheckValidity(guest, [], requirement) == errSecSuccess else { return nil }
        return SigningIdentity(signer: signer, identifier: identifier)
    }
}
