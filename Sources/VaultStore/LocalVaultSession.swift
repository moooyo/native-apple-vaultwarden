import Foundation

package struct LocalVaultSession: Sendable, Equatable {
    package let accountID: String
    package let id: UUID
    package let localAuthHash: String
    package let refreshToken: String?

    package init(accountID: String, id: UUID, localAuthHash: String, refreshToken: String?) {
        self.accountID = accountID
        self.id = id
        self.localAuthHash = localAuthHash
        self.refreshToken = refreshToken
    }
}
