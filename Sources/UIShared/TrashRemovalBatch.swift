public struct TrashRemovalBatch: Sendable {
    public let ids: [String]

    public init(ids: [String]) { self.ids = ids }

    public static let confirmationMessage = "永久删除后无法恢复。离线时会在下次同步时提交删除。"

    public static func receipt(for count: Int) -> String { "已从本机回收站移除 \(count) 个条目" }

    public struct Failure: Error, Equatable {
        public let confirmed: Int
        public let unattempted: Int

        public init(confirmed: Int, unattempted: Int) {
            self.confirmed = confirmed
            self.unattempted = unattempted
        }

        public var message: String {
            let progress = confirmed == 0 ? "" : TrashRemovalBatch.receipt(for: confirmed) + "。"
            let remaining = unattempted == 0 ? "" : "另有 \(unattempted) 个条目尚未尝试删除。"
            return progress + "有 1 个条目的删除结果未能确认。" + remaining + "请同步保险库后核对结果。"
        }
    }

    @MainActor public func perform(using remove: @MainActor (String) async throws -> Void) async throws -> Int {
        for (index, id) in ids.enumerated() {
            try Task.checkCancellation()
            do { try await remove(id) }
            catch {
                try Task.checkCancellation()
                throw Failure(confirmed: index, unattempted: ids.count - index - 1)
            }
        }
        return ids.count
    }
}
