import Foundation
import Darwin
import AppShared
import KeychainBridge

/// A passkey registration durably staged by the credential-provider extension.
///
/// The encoded value contains private key material and therefore lives only in the shared
/// Keychain. The App Group marker contains only `id` + `version`.
public struct StagedPasskeyRegistration: Codable, Sendable, Equatable {
    public let version: Int
    public let id: String
    public let accountID: String
    public let cipherID: String?
    public let relyingPartyID: String
    public let userName: String
    public let userDisplayName: String?
    public let userHandle: Data
    public let credentialID: Data
    public let privateKeyPKCS8: Data
    public let creationDate: Date

    public init(
        version: Int = 1,
        id: String,
        accountID: String,
        cipherID: String?,
        relyingPartyID: String,
        userName: String,
        userDisplayName: String? = nil,
        userHandle: Data,
        credentialID: Data,
        privateKeyPKCS8: Data,
        creationDate: Date = Date()
    ) {
        self.version = version
        self.id = id
        self.accountID = accountID
        self.cipherID = cipherID
        self.relyingPartyID = relyingPartyID
        self.userName = userName
        self.userDisplayName = userDisplayName
        self.userHandle = userHandle
        self.credentialID = credentialID
        self.privateKeyPKCS8 = privateKeyPKCS8
        self.creationDate = creationDate
    }
}

public enum PasskeyHandoffError: Error, Sendable, Equatable {
    case noActiveAccount
    case sessionChanged
    case invalidRegistration
    case keychainUnavailable
    case storageUnavailable
}

/// Cross-process durable queue used by the AutoFill extension and main app.
///
/// Write order is staging marker, Keychain secret, then an atomic rename to a ready marker.
/// A crash can therefore never orphan an undiscoverable private key. Read acknowledgement
/// deletes the secret first, then the marker.
public actor PasskeyRegistrationHandoff {
    private struct Marker: Codable, Sendable, Equatable {
        let version: Int
        let id: String
    }

    private let directoryURL: URL
    private let keychain: KeychainBridge
    private let makeID: @Sendable () -> UUID
    private let beforeReadyPromotion: @Sendable () async -> Void
    private let afterReadyPromotion: @Sendable () async -> Void
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(
        directoryURL: URL,
        keychain: KeychainBridge,
        makeID: @escaping @Sendable () -> UUID = { UUID() },
        beforeReadyPromotion: @escaping @Sendable () async -> Void = {},
        afterReadyPromotion: @escaping @Sendable () async -> Void = {}
    ) {
        self.directoryURL = directoryURL
        self.keychain = keychain
        self.makeID = makeID
        self.beforeReadyPromotion = beforeReadyPromotion
        self.afterReadyPromotion = afterReadyPromotion
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        self.encoder = encoder
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        self.decoder = decoder
    }

    /// Persist a registration. Success means both the Keychain secret and atomic marker are
    /// durable enough for the main app to discover; any failure rolls back what it can.
    @discardableResult
    public func stage(
        expectedAccountID: String,
        expectedSessionID: String,
        cipherID: String?,
        relyingPartyID: String,
        userName: String,
        userDisplayName: String? = nil,
        userHandle: Data,
        credentialID: Data,
        privateKeyPKCS8: Data,
        creationDate: Date = Date()
    ) async throws -> StagedPasskeyRegistration {
        guard !expectedAccountID.isEmpty,
              !expectedSessionID.isEmpty,
              !relyingPartyID.isEmpty,
              !userName.isEmpty,
              !userHandle.isEmpty,
              !credentialID.isEmpty,
              !privateKeyPKCS8.isEmpty else {
            throw PasskeyHandoffError.invalidRegistration
        }

        let matchesBeforeReady: Bool
        do {
            matchesBeforeReady = try await matchesExpectedSession(
                accountID: expectedAccountID,
                sessionID: expectedSessionID
            )
        } catch {
            throw error
        }
        guard matchesBeforeReady else {
            throw PasskeyHandoffError.noActiveAccount
        }

        let id = makeID().uuidString.lowercased()
        let registration = StagedPasskeyRegistration(
            id: id,
            accountID: expectedAccountID,
            cipherID: cipherID,
            relyingPartyID: relyingPartyID,
            userName: userName,
            userDisplayName: userDisplayName,
            userHandle: userHandle,
            credentialID: credentialID,
            privateKeyPKCS8: privateKeyPKCS8,
            creationDate: creationDate
        )

        let secret: Data
        do { secret = try encoder.encode(registration) }
        catch { throw PasskeyHandoffError.invalidRegistration }

        let fileManager = FileManager.default
        let stagingURL = stagingMarkerURL(id: id)
        do {
            try fileManager.createDirectory(
                at: directoryURL,
                withIntermediateDirectories: true
            )
        } catch {
            throw PasskeyHandoffError.storageUnavailable
        }

        let writerLockURL = stagingLockURL(id: id)
        let writerLock = Darwin.open(
            writerLockURL.path,
            O_CREAT | O_RDWR,
            S_IRUSR | S_IWUSR
        )
        guard writerLock >= 0, Darwin.lockf(writerLock, F_TLOCK, 0) == 0 else {
            if writerLock >= 0 { Darwin.close(writerLock) }
            throw PasskeyHandoffError.storageUnavailable
        }
        defer {
            _ = Darwin.lockf(writerLock, F_ULOCK, 0)
            Darwin.close(writerLock)
            try? fileManager.removeItem(at: writerLockURL)
        }

        do {
            let marker = try encoder.encode(Marker(version: 1, id: id))
            try marker.write(to: stagingURL, options: [.atomic, .completeFileProtection])
        } catch {
            throw PasskeyHandoffError.storageUnavailable
        }

        let secretAccount = Self.secretAccount(id: id)
        do {
            try await keychain.setSecret(
                secret,
                account: secretAccount,
                biometryGated: false
            )
        } catch {
            // A failing Keychain implementation is not assumed to be transactional; clean
            // up a value even if it was written immediately before the error surfaced.
            await keychain.deleteSecret(account: secretAccount)
            try? fileManager.removeItem(at: stagingURL)
            throw PasskeyHandoffError.keychainUnavailable
        }

        // Test seam at the crash/account-switch boundary; production's default is a no-op.
        await beforeReadyPromotion()

        // This nonce read is the final authorization point. Once the staging file is renamed
        // below, the ready marker is visible cross-process and ownership transfers to the main
        // app; the extension must never roll it back after publication. The app alone may
        // finalize, retry, or quarantine that committed registration.
        let matchesBeforePromotion: Bool
        do {
            matchesBeforePromotion = try await matchesExpectedSession(
                accountID: expectedAccountID,
                sessionID: expectedSessionID
            )
        } catch {
            await keychain.deleteSecret(account: secretAccount)
            try? fileManager.removeItem(at: stagingURL)
            throw error
        }
        guard matchesBeforePromotion else {
            await keychain.deleteSecret(account: secretAccount)
            try? fileManager.removeItem(at: stagingURL)
            throw PasskeyHandoffError.sessionChanged
        }

        do {
            try fileManager.moveItem(at: stagingURL, to: markerURL(id: id))
        } catch {
            await keychain.deleteSecret(account: secretAccount)
            try? fileManager.removeItem(at: stagingURL)
            throw PasskeyHandoffError.storageUnavailable
        }

        // The rename above is the commit point. This test seam deliberately runs after
        // publication: a later lock/session rotation must not revoke the durable key now
        // owned by the main-app finalize/quarantine path.
        await afterReadyPromotion()

        return registration
    }

    /// Decode every discoverable registration. Corrupt or secret-less markers are cleaned up;
    /// transient Keychain failures leave the queue intact and surface an error for retry.
    public func pendingRegistrations() async throws -> [StagedPasskeyRegistration] {
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: directoryURL.path) else { return [] }
        try await recoverStagingMarkers(fileManager: fileManager)

        let files: [URL]
        do {
            files = try fileManager.contentsOfDirectory(
                at: directoryURL,
                includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
                options: [.skipsHiddenFiles]
            ).filter { $0.pathExtension == "pending" }
             .sorted { $0.lastPathComponent < $1.lastPathComponent }
        } catch {
            throw PasskeyHandoffError.storageUnavailable
        }

        var registrations: [StagedPasskeyRegistration] = []
        for file in files {
            let values = try? file.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard values?.isRegularFile == true, values?.isSymbolicLink != true else {
                try? fileManager.removeItem(at: file)
                continue
            }
            let data: Data
            do { data = try Data(contentsOf: file) }
            catch { throw PasskeyHandoffError.storageUnavailable }
            guard let marker = try? decoder.decode(Marker.self, from: data),
                  marker.version == 1,
                  Self.isValidID(marker.id),
                  file.deletingPathExtension().lastPathComponent == marker.id else {
                try? fileManager.removeItem(at: file)
                continue
            }

            let secretAccount = Self.secretAccount(id: marker.id)
            let secret: Data?
            do { secret = try await keychain.getSecret(account: secretAccount) }
            catch { throw PasskeyHandoffError.keychainUnavailable }
            guard let secret else {
                try? fileManager.removeItem(at: file)
                continue
            }
            guard let registration = try? decoder.decode(
                StagedPasskeyRegistration.self,
                from: secret
            ), registration.version == 1, registration.id == marker.id else {
                await keychain.deleteSecret(account: secretAccount)
                try? fileManager.removeItem(at: file)
                continue
            }
            registrations.append(registration)
        }
        return registrations
    }

    /// Idempotently acknowledge a successfully imported registration.
    public func acknowledge(id: String) async throws {
        guard Self.isValidID(id) else { throw PasskeyHandoffError.invalidRegistration }
        await keychain.deleteSecret(account: Self.secretAccount(id: id))
        do {
            let url = markerURL(id: id)
            if FileManager.default.fileExists(atPath: url.path) {
                try FileManager.default.removeItem(at: url)
            }
        } catch {
            // The marker is now harmless: the next read observes its missing secret and
            // removes it. Surface the failure so callers may retry cleanup.
            throw PasskeyHandoffError.storageUnavailable
        }
    }

    private func markerURL(id: String) -> URL {
        directoryURL.appendingPathComponent(id).appendingPathExtension("pending")
    }

    private func stagingMarkerURL(id: String) -> URL {
        directoryURL.appendingPathComponent(id).appendingPathExtension("staging")
    }

    private func stagingLockURL(id: String) -> URL {
        directoryURL.appendingPathComponent(id).appendingPathExtension("lock")
    }

    /// Recover only stale staging files, leaving a live extension a grace window to finish
    /// its Keychain write + rename. Every secret-bearing crash state remains discoverable.
    private func recoverStagingMarkers(fileManager: FileManager) async throws {
        let files: [URL]
        do {
            files = try fileManager.contentsOfDirectory(
                at: directoryURL,
                includingPropertiesForKeys: [
                    .isRegularFileKey,
                    .isSymbolicLinkKey,
                    .contentModificationDateKey,
                ],
                options: [.skipsHiddenFiles]
            ).filter { $0.pathExtension == "staging" }
        } catch {
            throw PasskeyHandoffError.storageUnavailable
        }

        let staleBefore = Date().addingTimeInterval(-10)
        for file in files {
            let values = try? file.resourceValues(forKeys: [
                .isRegularFileKey,
                .isSymbolicLinkKey,
                .contentModificationDateKey,
            ])
            guard values?.isRegularFile == true,
                  values?.isSymbolicLink != true,
                  let modified = values?.contentModificationDate,
                  modified <= staleBefore else { continue }

            let data: Data
            do { data = try Data(contentsOf: file) }
            catch { throw PasskeyHandoffError.storageUnavailable }
            guard let marker = try? decoder.decode(Marker.self, from: data),
                  marker.version == 1,
                  Self.isValidID(marker.id),
                  file.deletingPathExtension().lastPathComponent == marker.id else {
                try? fileManager.removeItem(at: file)
                continue
            }

            let lockURL = stagingLockURL(id: marker.id)
            let descriptor = Darwin.open(
                lockURL.path,
                O_CREAT | O_RDWR,
                S_IRUSR | S_IWUSR
            )
            guard descriptor >= 0 else {
                throw PasskeyHandoffError.storageUnavailable
            }
            guard Darwin.lockf(descriptor, F_TLOCK, 0) == 0 else {
                Darwin.close(descriptor)
                // A live extension still owns this staging id, regardless of mtime.
                continue
            }
            defer {
                _ = Darwin.lockf(descriptor, F_ULOCK, 0)
                Darwin.close(descriptor)
                try? fileManager.removeItem(at: lockURL)
            }

            let secretAccount = Self.secretAccount(id: marker.id)
            let secret: Data?
            do { secret = try await keychain.getSecret(account: secretAccount) }
            catch { throw PasskeyHandoffError.keychainUnavailable }
            guard let secret else {
                try? fileManager.removeItem(at: file)
                continue
            }
            guard let registration = try? decoder.decode(
                StagedPasskeyRegistration.self,
                from: secret
            ), registration.version == 1, registration.id == marker.id else {
                await keychain.deleteSecret(account: secretAccount)
                try? fileManager.removeItem(at: file)
                continue
            }
            do {
                try fileManager.moveItem(at: file, to: markerURL(id: marker.id))
            } catch {
                throw PasskeyHandoffError.storageUnavailable
            }
        }
    }

    private static func secretAccount(id: String) -> String {
        AppShared.KeychainAccount.passkeyRegistrationPrefix + id
    }

    private func matchesExpectedSession(
        accountID: String,
        sessionID: String
    ) async throws -> Bool {
        let activeAccount: Data?
        let activeSession: Data?
        let biometricAccount: Data?
        do {
            activeAccount = try await keychain.getSecret(
                account: AppShared.KeychainAccount.activeAccountID
            )
            activeSession = try await keychain.getSecret(
                account: AppShared.KeychainAccount.activeSessionID
            )
            biometricAccount = try await keychain.getSecret(
                account: AppShared.KeychainAccount.biometricAccountID
            )
        } catch {
            throw PasskeyHandoffError.keychainUnavailable
        }
        return activeAccount.flatMap { String(data: $0, encoding: .utf8) } == accountID
            && activeSession.flatMap { String(data: $0, encoding: .utf8) } == sessionID
            && biometricAccount.flatMap { String(data: $0, encoding: .utf8) } == accountID
    }

    private static func isValidID(_ id: String) -> Bool {
        UUID(uuidString: id) != nil
    }
}
