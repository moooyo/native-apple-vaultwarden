import VaultModels
import VaultRepository

/// An on-device assessment of active personal logins with a saved, non-empty password.
/// This is a heuristic, not a breach check or a guarantee of password strength.
public struct VaultHealthReport: Equatable, Sendable {
    public enum Weakness: Equatable, Sendable {
        case tooShort
        case limitedCharacterVariety
        case commonPattern
        case repeatedPattern
    }

    public struct Finding: Equatable, Identifiable, Sendable {
        public let id: String
        public let name: String
        public let weaknesses: [Weakness]
        /// Number of eligible logins with this exact password, including this login.
        public let reuseCount: Int
    }

    public let checkedCount: Int
    public let weakCount: Int
    public let reusedCount: Int
    public let findings: [Finding]

    /// Use a local-only vault adapter without background write or sync hooks.
    public static func load(auth: any AuthService, vault: any VaultService,
                            for lease: AccountSessionLease) async throws -> Self {
        try await load(vault: vault, for: lease, currentSession: auth.transferSession)
    }

    @concurrent
    package static func load(vault: any VaultService, for lease: AccountSessionLease,
                             currentSession: @Sendable () async -> AccountSessionLease?) async throws -> Self {
        try Task.checkCancellation()
        let previous = await currentSession()
        try Task.checkCancellation()
        guard previous == lease else { throw RepositoryError.locked }

        let report = try await readAndAnalyze(vault: vault)
        try Task.checkCancellation()
        let current = await currentSession()
        try Task.checkCancellation()
        guard current == lease else { throw RepositoryError.locked }
        return report
    }

    private static func readAndAnalyze(vault: any VaultService) async throws -> Self {
        // ciphers() is the narrowest available enumeration. Project it synchronously so the
        // decrypted snapshot is not retained across the next session check.
        let ciphers = try await vault.ciphers()
        return try analyze(ciphers)
    }

    package static func analyze(_ ciphers: [PlaintextCipher]) throws -> Self {
        func password(at index: Int) -> String { ciphers[index].login?.password ?? "" }

        var candidates: [Int] = []
        for index in ciphers.indices {
            try Task.checkCancellation()
            let cipher = ciphers[index]
            guard cipher.type == CipherType.login.rawValue, cipher.organizationID == nil,
                  cipher.deletedDate == nil, cipher.archivedDate == nil,
                  cipher.id?.isEmpty == false, !password(at: index).isEmpty else { continue }
            candidates.append(index)
        }

        // Sort indices into the existing snapshot rather than copying passwords or creating
        // reusable fingerprints. Swift String equality would conflate canonically equivalent bytes.
        try candidates.sort { lhs, rhs in
            try Task.checkCancellation()
            return password(at: lhs).utf8.lexicographicallyPrecedes(password(at: rhs).utf8)
        }

        var findings: [Finding] = []
        var weakCount = 0
        var reusedCount = 0
        var start = 0
        while start < candidates.count {
            try Task.checkCancellation()
            let value = password(at: candidates[start])
            let bytes = value.utf8
            var end = start + 1
            while end < candidates.count, bytes.elementsEqual(password(at: candidates[end]).utf8) {
                try Task.checkCancellation()
                end += 1
            }
            let count = end - start
            let reasons = try weaknesses(for: value)
            if !reasons.isEmpty { weakCount += count }
            if count > 1 { reusedCount += count }
            if !reasons.isEmpty || count > 1 {
                for index in candidates[start..<end] {
                    try Task.checkCancellation()
                    let item = ciphers[index]
                    if let id = item.id {
                        findings.append(Finding(id: id, name: item.name, weaknesses: reasons, reuseCount: count))
                    }
                }
            }
            start = end
        }

        // Locale-independent order, separate from the transient password order above.
        try findings.sort { lhs, rhs in
            try Task.checkCancellation()
            let a = lhs.name.utf8, b = rhs.name.utf8
            return a.elementsEqual(b) ? lhs.id.utf8.lexicographicallyPrecedes(rhs.id.utf8) : a.lexicographicallyPrecedes(b)
        }
        try Task.checkCancellation()
        return Self(checkedCount: candidates.count, weakCount: weakCount, reusedCount: reusedCount, findings: findings)
    }

    private static let commonPatterns = ["password", "passw0rd", "qwerty", "letmein", "123456", "abcdef"]

    private static func weaknesses(for password: String) throws -> [Weakness] {
        var reasons: [Weakness] = []
        if password.prefix(12).count < 12 { reasons.append(.tooShort) }
        let folded = password.lowercased()
        var distinct: Set<Character> = []
        for character in folded {
            try Task.checkCancellation()
            distinct.insert(character)
            if distinct.count == 4 { break }
        }
        if distinct.count < 4 { reasons.append(.limitedCharacterVariety) }
        if commonPatterns.contains(where: { folded.contains($0) }) { reasons.append(.commonPattern) }
        if reasons.isEmpty, try repeatsShortPattern(folded) { reasons.append(.repeatedPattern) }
        return reasons
    }

    private static func repeatsShortPattern(_ password: String) throws -> Bool {
        let count = password.count
        for width in 2...8 where count >= 2 * width && count.isMultiple(of: width) {
            if try zip(password, password.dropFirst(width)).allSatisfy({ first, second in
                try Task.checkCancellation()
                return first == second
            }) { return true }
        }
        return false
    }
}
