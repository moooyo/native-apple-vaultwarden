import Foundation
import UIShared

extension MacLocalization {
    @MainActor
    static func syncStatusDescription(_ model: SyncStatusModel, locale: Locale = interfaceLocale) -> String {
        switch model.presentationStatus {
        case .syncing: text("Syncing…", locale: locale)
        case .resolving: text("Resolving sync issue…", locale: locale)
        case .needsAttention: text("Sync issues need attention", locale: locale)
        case .error(let message): text(message, locale: locale)
        case .pendingChanges: text("Changes waiting to upload", locale: locale)
        case .unavailable: text("Could not confirm sync status", locale: locale)
        case .synced(let date): format("Synced · %@", date.formatted(.relative(presentation: .named).locale(locale)), locale: locale)
        case .notSynced: text("Not yet synced", locale: locale)
        }
    }

    static func hiddenItemDate(_ date: Date, trashed: Bool, locale: Locale = interfaceLocale) -> String {
        format(trashed ? "Deleted %@" : "Archived %@", formattedDate(date, locale: locale), locale: locale)
    }

    static func trashReceipt(_ count: Int) -> String {
        format("Removed %lld items from local Trash", count)
    }

    static func trashFailure(_ failure: TrashRemovalBatch.Failure) -> String {
        let progress = failure.confirmed == 0 ? "" : format("Removed %lld items from local Trash. ", failure.confirmed)
        let remaining = failure.unattempted == 0 ? "" : format("%lld more deletions were not attempted. ", failure.unattempted)
        return progress + text("Deletion could not be confirmed for one item. ") + remaining + text("Sync the vault and check the result.")
    }
}
