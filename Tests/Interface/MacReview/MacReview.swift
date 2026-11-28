import AppKit

@main
enum MacReview {
    @MainActor static func main() {
        guard CommandLine.arguments.count >= 2 else {
            FileHandle.standardError.write(Data("Usage: MacReview OUTPUT_DIRECTORY [--dark] [--auth-boards | --code-boards | --settings-boards | --ssh-boards | --copy-list-board] | --check-interactions [EVIDENCE_DIRECTORY] | --check-ssh | --check-ssh-focus\n".utf8))
            exit(2)
        }
        UserDefaults.standard.register(defaults: [
            "AppleLanguages": ["zh-Hans"], "AppleLocale": "zh_CN",
            MacLanguagePreference.defaultsKey: MacLanguagePreference.simplifiedChinese.rawValue
        ])
        let application = NSApplication.shared
        let checkingSSHFocus = CommandLine.arguments[1] == "--check-ssh-focus"
        application.setActivationPolicy(checkingSSHFocus ? .accessory : .prohibited)
        let dark = CommandLine.arguments.contains("--dark")
        application.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
        Task { @MainActor in
            do {
                if checkingSSHFocus {
                    try await MacSSHAgentChecks.checkNonactivation()
                    exit(0)
                }
                if CommandLine.arguments[1] == "--check-ssh" {
                    try MacSSHSigningKeyChecks.run()
                    try await MacSSHAgentChecks.run()
                    exit(0)
                }
                if CommandLine.arguments[1] == "--check-interactions" {
                    let boards = try await ReviewBoards()
                    let evidence = CommandLine.arguments.dropFirst(2).first.map { URL(fileURLWithPath: $0, isDirectory: true) }
                    if let evidence { try FileManager.default.createDirectory(at: evidence, withIntermediateDirectories: true) }
                    try MacSSHSigningKeyChecks.run()
                    try await MacSSHAgentChecks.run()
                    try await ClipboardFunctionalChecks.run()
                    try await MacSessionTimeoutChecks.run()
                    try await MacLockedRelaunchChecks.run()
                    try await boards.checkQuickCopy()
                    try await boards.checkInterfaceLanguage()
                    try await boards.checkFunctionalFlows()
                    try await boards.checkTouchIDSettingsAndFallback()
                    try await boards.checkInteractions(evidence: evidence)
                    print("Codes and Vault expiry/copy, authenticator creation, Send selection and race recovery, workspace search, trash batch and read recovery passed.")
                    exit(0)
                }
                let directory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                let boards = try await ReviewBoards()
                let renderer = WindowRenderer(directory: directory, dark: dark)
                if CommandLine.arguments.contains("--auth-boards") { try await boards.renderAuthenticationBoards(using: renderer) }
                else if CommandLine.arguments.contains("--settings-boards") { try await boards.renderSettingsBoards(using: renderer) }
                else if CommandLine.arguments.contains("--ssh-boards") { try await boards.renderSSHBoards(using: renderer) }
                else if CommandLine.arguments.contains("--code-boards") { try await boards.renderCodeBoards(using: renderer) }
                else if CommandLine.arguments.contains("--copy-list-board") { try await boards.renderNarrowCopyList(using: renderer) }
                else { try await boards.render(using: renderer) }
                exit(0)
            } catch {
                FileHandle.standardError.write(Data("MacReview: \(error)\n".utf8))
                exit(1)
            }
        }
        application.run()
    }
}
