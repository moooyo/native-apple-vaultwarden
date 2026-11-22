import DesignSystem
import SwiftUI
import VaultModels
import VaultRepository

extension BrandBadge {
    init(_ cipher: PlaintextCipher, diameter: CGFloat) {
        let style: BrandBadge.Style = switch CipherType(rawValue: cipher.type) {
        case .secureNote: .note
        case .card: .card
        case .identity: .identity
        case .sshKey: .terminal
        case .login, .unknown: .account
        }
        self.init(cipher.name, diameter: diameter, style: style)
    }
}
