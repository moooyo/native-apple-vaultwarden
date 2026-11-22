import AppKit

@main
enum MacReview {
    @MainActor static func main() {
        guard CommandLine.arguments.count >= 2 else {
            FileHandle.standardError.write(Data("Usage: MacReview OUTPUT_DIRECTORY [--dark] [--code-boards] | --check-interactions [EVIDENCE_DIRECTORY]\n".utf8))
            exit(2)
        }
        UserDefaults.standard.register(defaults: ["AppleLanguages": ["zh-Hans"], "AppleLocale": "zh_CN"])
        let application = NSApplication.shared
        application.setActivationPolicy(.prohibited)
        let dark = CommandLine.arguments.contains("--dark")
        application.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
        Task { @MainActor in
            do {
                if CommandLine.arguments[1] == "--check-interactions" {
                    let boards = try await ReviewBoards()
                    let evidence = CommandLine.arguments.dropFirst(2).first.map { URL(fileURLWithPath: $0, isDirectory: true) }
                    if let evidence { try FileManager.default.createDirectory(at: evidence, withIntermediateDirectories: true) }
                    try await ClipboardFunctionalChecks.run()
                    try await boards.checkFunctionalFlows()
                    try await boards.checkInteractions(evidence: evidence)
                    print("Codes and Vault expiry/copy, authenticator creation, Send selection and race recovery, workspace search, trash batch and read recovery passed.")
                    exit(0)
                }
                let directory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                let boards = try await ReviewBoards()
                let renderer = WindowRenderer(directory: directory, dark: dark)
                if CommandLine.arguments.contains("--code-boards") { try await boards.renderCodeBoards(using: renderer) }
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
