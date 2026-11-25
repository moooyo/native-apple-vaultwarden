/// Outcome of an explicit, online per-item key upgrade.
public struct CipherKeyUpgradeResult: Sendable, Equatable {
    public internal(set) var upgraded = 0
    /// Items left alone, including unsupported, unreadable and pending items.
    public internal(set) var skipped = 0
    public internal(set) var failed = 0
    /// The batch stopped after an update could not be confirmed. Sync before taking further action.
    public internal(set) var requiresSync = false
}
