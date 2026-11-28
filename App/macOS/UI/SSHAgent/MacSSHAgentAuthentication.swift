import Darwin
import Foundation
import KeychainBridge
import LocalAuthentication
import OpenDirectory
import VaultRepository

@MainActor
struct MacSSHAgentAuthentication {
    let auth: AuthRepository
    let beforeVerification: () async -> Void

    func verify(_ approval: MacSSHAgentApproval, factor: MacSSHApprovalPanelModel.Factor) async -> MacSSHApprovalPanelModel.Verification {
        await beforeVerification()
        guard !Task.isCancelled, await auth.currentSessionLease() == approval.lease,
              !(await auth.requiresNewLogin()) else { return .cancelled }
        switch factor {
        case .touchID:
            let reason = macSSHAgentText("Approve the SSH key request in OpenVault")
            let fallback = macSSHAgentText("Use Password…")
            do {
                if approval.locked {
                    try await auth.unlockForSSHAgentWithTouchID(reason: reason, fallbackTitle: fallback, expectedSession: approval.lease)
                    return .verified
                }
                return await TouchID(fallback: fallback).evaluate(reason: reason)
            } catch KeychainError.passwordFallback, KeychainError.unavailable, KeychainError.notFound {
                return .passwordRequired
            } catch {
                return .cancelled
            }
        case .password(let password):
            if approval.locked {
                do {
                    try await auth.unlockWithMasterPassword(password, expectedSession: approval.lease)
                    return .verified
                } catch RepositoryError.authenticationFailed { return .passwordRejected }
                catch { return .cancelled }
            }
            return await Self.verifyLoginPassword(password) ? .verified : .passwordRejected
        }
    }

    private static func verifyLoginPassword(_ password: String) async -> Bool {
        // Resolve the account from the process UID, never from a socket peer or user input.
        guard !password.isEmpty, !Task.isCancelled else { return false }
        let check = Task.detached(priority: .userInitiated) {
            let uid = getuid()
            guard uid != 0, uid == geteuid(), !Task.isCancelled else { return false }
            var account = passwd()
            var result: UnsafeMutablePointer<passwd>?
            var storage = [CChar](repeating: 0, count: Int(max(4096, sysconf(_SC_GETPW_R_SIZE_MAX))))
            let name = storage.withUnsafeMutableBufferPointer { buffer -> String? in
                guard getpwuid_r(uid, &account, buffer.baseAddress, buffer.count, &result) == 0,
                      result != nil, let bytes = account.pw_name else { return nil }
                return String(validatingCString: bytes)
            }
            guard let name, let node = try? ODNode(session: ODSession.default(), type: ODNodeType(kODNodeTypeAuthentication)),
                  let record = try? node.record(withRecordType: kODRecordTypeUsers, name: name, attributes: [kODAttributeTypeUniqueID]),
                  let ids = try? record.values(forAttribute: kODAttributeTypeUniqueID) as? [String], ids == [String(uid)],
                  !Task.isCancelled else { return false }
            do { try record.verifyPassword(password); return !Task.isCancelled }
            catch { return false }
        }
        return await withTaskCancellationHandler { await check.value } onCancel: { check.cancel() }
    }

    private final class TouchID: @unchecked Sendable {
        private let context = LAContext()

        init(fallback: String) {
            context.localizedFallbackTitle = fallback
            context.touchIDAuthenticationAllowableReuseDuration = 0
        }

        func evaluate(reason: String) async -> MacSSHApprovalPanelModel.Verification {
            defer { context.invalidate() }
            guard !Task.isCancelled else { return .cancelled }
            guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil), context.biometryType == .touchID else {
                return .passwordRequired
            }
            return await withTaskCancellationHandler {
                do {
                    let passed = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
                    return passed && !Task.isCancelled ? .verified : .cancelled
                } catch let error as LAError {
                    switch error.code {
                    case .userFallback, .biometryLockout, .biometryNotAvailable, .biometryNotEnrolled: return .passwordRequired
                    default: return .cancelled
                    }
                } catch { return .cancelled }
            } onCancel: { self.context.invalidate() }
        }
    }
}
