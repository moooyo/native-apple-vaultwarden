import Foundation
import CryptoCore
import VaultRepository

/// Maps a thrown error into a short, user-presentable message. Centralized so every view
/// model surfaces consistent strings (and so secrets never leak into UI text — only the
/// well-known `RepositoryError` cases produce specific copy; everything else is generic).
extension UnlockModel {
    static func message(for error: Error) -> String { errorString(error) }
}
extension LoginModel {
    static func message(for error: Error) -> String { errorString(error) }
}
extension VaultListModel {
    static func message(for error: Error) -> String { errorString(error) }
}

/// Shared error → message mapping.
func errorString(_ error: Error) -> String {
    guard let repo = error as? RepositoryError else { return "操作未完成，请重试。" }
    switch repo {
    case .unsupportedKDF:
        return "此账户的加密设置尚不受支持（Argon2id）。"
    case .locked:
        return "保险库已锁定。"
    case .authenticationFailed:
        return "验证失败，请检查输入后重试。"
    case .notAuthenticated:
        return "请先登录。"
    case .vaultAccessDenied:
        return "服务器拒绝了保险库访问请求。"
    case .reauthenticationRequired:
        return String(localized: "Your account's unlock settings changed on the server. Sign in again. Pending edits were kept on this device.")
    case .cipherNotFound:
        return "未找到该条目。"
    case .cipherChanged:
        return "条目已更改。请重新打开后再编辑。"
    case .invalidFolderName:
        return "请输入文件夹名称。"
    case .incompleteSSHKey:
        return "SSH 密钥必须包含私钥、公钥和指纹。"
    case .pendingCipherChanges:
        return "此条目有未上传的更改。请先同步，或前往设置处理同步问题。"
    case .outboxIssueChanged:
        return "同步问题已更改，请刷新后再试。"
    case .outboxRecoveryUnavailable:
        return "暂时无法安全处理此更改。本地数据仍保留，请稍后重试。"
    case .organizationCipherKeyUnavailable:
        return "缺少组织密钥，暂时无法编辑此条目。"
    case .missingUserKey:
        return "服务器响应中缺少保险库密钥。"
    case .underlying(let kind, let description):
        switch kind {
        case .network:
            if description == "HTTPS is required for this server" { return "This server must use HTTPS." }
            return "服务器请求失败，请检查连接后重试。"
        case .store: return "无法访问本机存储。"
        case .crypto:
            // RepositoryError.crypto serializes the case name; never display the description.
            switch description {
            case String(describing: CryptoError.insufficientKdfParameters):
                return String(localized: "This account’s PBKDF2 iteration count is below OpenVault’s minimum of \(KDF.minimumPBKDF2Iterations). Review the key derivation settings in your web vault.")
            case String(describing: CryptoError.excessiveKdfParameters):
                return String(localized: "This account’s PBKDF2 iteration count exceeds OpenVault’s limit of \(KDF.maximumPBKDF2Iterations). Review the key derivation settings in your web vault.")
            default:
                return "无法解密数据。"
            }
        case .sync: return "同步失败。"
        }
    }
}
