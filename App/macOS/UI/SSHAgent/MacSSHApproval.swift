import Foundation
import VaultRepository

enum MacSSHApprovalDuration: String, CaseIterable, Sendable {
    case once, minutes15, untilVaultLock

    var label: String {
        switch self {
        case .once: "Only Once"
        case .minutes15: "15 Minutes"
        case .untilVaultLock: "Until the Vault Locks"
        }
    }
}

enum MacSSHAgentPolicy: String, CaseIterable, Sendable {
    case askEveryTime
    case remember15Min = "sameApp15Min" // Existing preference value; the label and cache scope are independent.
    case untilVaultUnlockedPeriod

    var defaultDuration: MacSSHApprovalDuration {
        switch self {
        case .askEveryTime: .once
        case .remember15Min: .minutes15
        case .untilVaultUnlockedPeriod: .untilVaultLock
        }
    }

    var label: String {
        switch self {
        case .askEveryTime: "Ask Every Time"
        case .remember15Min: "Remember for 15 Minutes"
        case .untilVaultUnlockedPeriod: "Don't Ask Again While the Vault Is Unlocked"
        }
    }
}

struct MacSSHAgentApproval: Sendable {
    let id = UUID()
    let keyName: String
    let keyAlgorithm: String
    let fingerprint: String
    let destination: MacSSHAgentProtocol.Destination
    let peer: MacSSHAgentPeer
    let locked: Bool
    let lease: AccountSessionLease
    let defaultDuration: MacSSHApprovalDuration

    var shortenedFingerprint: String {
        let digest = fingerprint.dropFirst("SHA256:".count)
        return "SHA256:\(digest.prefix(6))…\(digest.suffix(4))"
    }
}

struct MacSSHApprovalCountdown {
    static let duration: Duration = .seconds(30)
    let seconds: Int
    let fraction: Double
    let warning: Double

    init(elapsed: Duration, reduceMotion: Bool) {
        let (whole, subsecond) = elapsed.components
        let elapsedSeconds = Double(whole) + Double(subsecond) / 1e18
        seconds = Int(ceil(min(30, max(0, 30 - elapsedSeconds))))
        fraction = min(1, max(0, (30 - elapsedSeconds) / 30))
        warning = reduceMotion ? (seconds <= 5 ? 1 : 0) : min(1, max(0, (elapsedSeconds - 24) / 2))
    }
}

func macSSHAgentText(_ key: String, _ arguments: CVarArg..., locale: Locale = MacLocalization.interfaceLocale) -> String {
    String(format: MacLocalization.text(key, table: "MacSSHAgent", locale: locale), locale: locale, arguments: arguments)
}
