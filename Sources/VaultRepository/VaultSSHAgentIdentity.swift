public struct VaultSSHAgentIdentity: Sendable, Equatable {
    public let id: String
    public let name: String
    public let publicKey: String
    public let revision: String

    public init(id: String, name: String, publicKey: String, revision: String) {
        self.id = id
        self.name = name
        self.publicKey = publicKey
        self.revision = revision
    }
}
