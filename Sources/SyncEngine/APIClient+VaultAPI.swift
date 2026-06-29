import Foundation
import Networking
import VaultModels

/// Make the real `Networking.APIClient` satisfy `VaultAPI`.
///
/// The method signatures already match exactly, so this conformance is empty —
/// it's declared here (in `SyncEngine`) rather than in `Networking` to keep the
/// networking layer free of any sync-engine coupling (the design's L2 modules are
/// siblings; only `SyncEngine` knows it wants this seam).
extension APIClient: VaultAPI {}
