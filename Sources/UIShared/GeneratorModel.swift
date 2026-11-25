import Foundation
import Observation
import Generators
import VaultRepository

/// Drives password, passphrase and enhanced-alias generation. Holds option bindings,
/// generation history and the latest value. A `RandomSource` is injected so tests are
/// deterministic; production uses the CSPRNG-backed default.
@MainActor
@Observable
public final class GeneratorModel {
    public typealias Mode = GeneratorHistoryEntry.Kind

    public var mode: Mode = .password {
        didSet { if mode != oldValue { regenerate() } }
    }

    /// Password options bound by the view.
    public var passwordOptions = PasswordGeneratorOptions(
        length: 20,
        useLowercase: true,
        useUppercase: true,
        useNumbers: true,
        useSpecial: true
    )
    /// Passphrase options bound by the view.
    public var passphraseOptions = PassphraseGeneratorOptions(wordCount: 4, separator: "-",
                                                               capitalize: true, includeNumber: true)

    /// Enhanced alias settings used by the username mode.
    public var usernameBase = "openvault"
    public var usernameDomain = "icloud.com"
    public var usernameSuffixLength = 4

    public private(set) var generated: String = ""
    public private(set) var generationRevision: UInt64 = 0
    public private(set) var history: [GeneratorHistoryEntry] = []
    public private(set) var historyError: String?
    public private(set) var isHistoryBusy = false
    /// A non-fatal message when the current options can't produce a value (e.g. no character
    /// set selected). `nil` when the last generation succeeded.
    public private(set) var errorMessage: String?

    private let source: RandomSource
    private let wordList: [String]
    private let historyService: (any GeneratorHistoryService)?
    private var historySession: AccountSessionLease?
    @ObservationIgnored private var pendingHistoryWrite: Task<Void, Never>?
    @ObservationIgnored private var historyVersion: UInt64 = 0

    /// - Parameters:
    ///   - source: random source (inject a deterministic mock in tests).
    ///   - wordList: an optional passphrase word list. `nil` selects the bundled compact list;
    ///     an explicitly empty list remains useful for testing the error state.
    public init(source: RandomSource = SystemRandomSource(), wordList: [String]? = nil,
                vault: (any VaultService)? = nil) {
        self.source = source
        self.wordList = wordList ?? Self.productionWordList
        self.historyService = vault as? any GeneratorHistoryService
    }

    public var estimatedEntropy: Int? {
        guard !generated.isEmpty else { return nil }
        let bits: Double
        switch mode {
        case .password:
            guard let estimate = PasswordGenerator.estimatedEntropy(for: passwordOptions) else { return nil }
            bits = estimate
        case .passphrase:
            guard !wordList.isEmpty else { return nil }
            bits = Double(passphraseOptions.wordCount) * log2(Double(wordList.count))
                + (passphraseOptions.includeNumber ? log2(10.0) : 0)
        case .username: return nil
        }
        return Int(bits.rounded(.down))
    }

    public var strengthLevel: Int? {
        guard let estimatedEntropy else { return nil }
        switch estimatedEntropy {
        case ..<40: return 1
        case ..<60: return 2
        case ..<90: return 3
        default: return 4
        }
    }

    public func prepareHistory() async {
        guard let historyService, !isHistoryBusy else { return }
        isHistoryBusy = true
        defer { isHistoryBusy = false }
        let version = historyVersion
        await pendingHistoryWrite?.value
        do {
            let snapshot = try await historyService.generatorHistory()
            guard !Task.isCancelled, version == historyVersion else { return }
            if let historySession, historySession != snapshot.session {
                generated = ""
            }
            historySession = snapshot.session
            history = snapshot.entries
            historyError = nil
        } catch {
            guard !Task.isCancelled, version == historyVersion else { return }
            history = []
            historySession = nil
            historyError = "无法读取本机生成历史。"
        }
    }

    /// (Re)generate using the current mode + options. Result lands in `generated`; on invalid
    /// options `generated` is cleared and `errorMessage` is set.
    public func regenerate(recordInHistory: Bool = false) {
        generationRevision &+= 1
        do {
            let value: String
            switch mode {
            case .password:
                value = try PasswordGenerator.generate(passwordOptions, using: source)
            case .passphrase:
                value = try PassphraseGenerator.generate(passphraseOptions,
                                                         wordList: wordList, using: source)
            case .username:
                value = try generateUsername()
            }
            generated = value
            if recordInHistory { record(value) }
            errorMessage = nil
        } catch {
            generated = ""
            if error is UsernameValidationError {
                errorMessage = "请输入有效的基础名称和邮箱域名。"
            } else {
                errorMessage = Self.message(for: error)
            }
        }
    }

    /// The value to place on the clipboard, or `nil` if nothing was generated.
    public func copyGenerated() -> String? {
        guard !generated.isEmpty else { return nil }
        record(generated)
        return generated
    }

    private func record(_ value: String) {
        guard history.first?.value != value || history.first?.kind != mode else { return }
        let entry = GeneratorHistoryEntry(kind: mode, value: value)
        guard historyService == nil || historySession != nil else {
            historyError = "无法将生成记录存入当前保险库。"
            return
        }
        history.insert(entry, at: 0)
        if history.count > GeneratorHistoryEntry.limit { history.removeLast() }
        guard let historyService, let historySession else { return }
        queueHistoryWrite { try await historyService.addGeneration(entry, session: historySession) }
    }

    public func clearHistory() async {
        guard !isHistoryBusy else { return }
        isHistoryBusy = true
        defer { isHistoryBusy = false }
        historyVersion &+= 1
        await pendingHistoryWrite?.value
        do {
            if let historyService, let historySession {
                try await historyService.clearGeneratorHistory(session: historySession)
            }
            history = []
            historyError = nil
        } catch {
            historyError = "无法清除本机生成历史，请重试。"
        }
    }

    private func queueHistoryWrite(_ operation: @escaping @Sendable () async throws -> Void) {
        historyVersion &+= 1
        let previousWrite = pendingHistoryWrite
        pendingHistoryWrite = Task { [weak self] in
            await previousWrite?.value
            do {
                try await operation()
            } catch {
                self?.historyError = "未能将生成记录存入保险库。"
            }
        }
    }

    private enum UsernameValidationError: Error { case invalidAlias }

    private func generateUsername() throws -> String {
        let alphabet = Array("abcdefghjkmnpqrstuvwxyz23456789")
        let suffix = String((0..<max(2, min(usernameSuffixLength, 10))).map { _ in
            alphabet[source.int(upperBound: alphabet.count)]
        })
        let base = usernameBase.trimmingCharacters(in: .whitespacesAndNewlines)
        let domain = usernameDomain.trimmingCharacters(in: .whitespacesAndNewlines)
        let localAllowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._-"))
        let domainAllowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
        let labels = domain.split(separator: ".", omittingEmptySubsequences: false)
        guard !base.isEmpty, base.utf8.count + suffix.count + 1 <= 64,
              !base.hasPrefix("."), !base.hasSuffix("."), !base.contains(".."),
              base.unicodeScalars.allSatisfy(localAllowed.contains),
              !domain.isEmpty, base.utf8.count + suffix.count + domain.utf8.count + 2 <= 254,
              domain.unicodeScalars.allSatisfy(domainAllowed.contains),
              labels.count >= 2,
              labels.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 63 && !$0.hasPrefix("-") && !$0.hasSuffix("-") }) else {
            throw UsernameValidationError.invalidAlias
        }
        return "\(base)+\(suffix)@\(domain)"
    }

    /// The ordered EFF long word list also used by Bitwarden account fingerprints.
    public static var standardDicewareWords: [String] { productionWordList }

    private static let productionWordList: [String] = {
        guard let url = Bundle.module.url(forResource: "eff_large_wordlist", withExtension: "txt"),
              let contents = try? String(contentsOf: url, encoding: .utf8) else {
            return []
        }
        return contents.split(whereSeparator: \.isNewline).compactMap { line in
            line.split(whereSeparator: \.isWhitespace).last.map(String.init)
        }
    }()

    static func message(for error: Error) -> String {
        guard let gen = error as? GeneratorError else { return "无法生成结果。" }
        switch gen {
        case .noCharacterSetSelected: return "请至少选择一类字符。"
        case .lengthTooShort: return "密码长度不足。"
        case .invalidOptions: return "无法使用当前选项生成结果。"
        }
    }
}
