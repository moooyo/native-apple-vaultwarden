import AppKit
import DesignSystem
import SwiftUI

struct MacSSHApprovalPanelView: View {
    static let size = CGSize(width: 480, height: 364)
    let model: MacSSHApprovalPanelModel
    var reduceMotionOverride: Bool? = nil
    var increasedContrastOverride: Bool? = nil
    @Environment(\.locale) private var locale
    @Environment(\.accessibilityReduceMotion) private var systemReduceMotion
    @Environment(\.colorSchemeContrast) private var contrast
    @FocusState private var passwordFocused: Bool

    private var reduceMotion: Bool { reduceMotionOverride ?? systemReduceMotion }
    private var highContrast: Bool { increasedContrastOverride ?? (contrast == .increased) }
    private var request: MacSSHAgentApproval { model.approval }
    private var appName: String { request.peer.appName ?? text("Unknown App") }
    private var command: String { request.peer.commandName ?? text("SSH Client") }
    private var approveLabel: String { request.locked ? "Unlock and Approve" : "Approve" }

    var body: some View {
        Group {
            switch model.phase {
            case let .done(duration): receipt(duration: duration)
            case .denied: receipt(duration: nil)
            default: form
            }
        }
        .frame(width: Self.size.width, height: Self.size.height)
        .background(Color(nsColor: .windowBackgroundColor))
        .clipShape(.rect(cornerRadius: 22))
        .overlay {
            RoundedRectangle(cornerRadius: 22).strokeBorder(Color(nsColor: .separatorColor))
                .allowsHitTesting(false)
        }
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 0) {
            header.padding(.bottom, 16)
            details
            switch model.phase {
            case .ask: durationPicker.padding(.top, 14)
            case .touch: touchIDStatus.padding(.top, 12)
            case .password: passwordRow.padding(.top, 14)
            case .done, .denied: EmptyView()
            }
            Spacer(minLength: 8)
            buttons.frame(maxWidth: .infinity, alignment: .trailing)
        }
        .padding(EdgeInsets(top: 22, leading: 24, bottom: 20, trailing: 24))
    }

    private var header: some View {
        HStack(spacing: 14) {
            OpenVaultMark(size: 52)
                .overlay(alignment: .bottomTrailing) {
                    Image(systemName: request.locked ? "lock.fill" : "key.fill")
                        .font(.system(size: 12, weight: .semibold))
                        .frame(width: 24, height: 24)
                        .background(Color(nsColor: .controlBackgroundColor), in: .circle)
                        .overlay { Circle().strokeBorder(Color(nsColor: .separatorColor), lineWidth: 0.5) }
                        .shadow(color: .primary.opacity(0.14), radius: 2, y: 1)
                        .offset(x: 2, y: 2)
                }
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(verbatim: format("“%@” wants to use an SSH key", appName))
                    .font(.headline).lineLimit(1).accessibilityAddTraits(.isHeader)
                Text(verbatim: subtitle).font(.subheadline).foregroundStyle(.secondary).lineLimit(1)
            }
        }
    }

    private var subtitle: String {
        if let host = request.verifiedHost {
            return request.locked ? format("%@ is connecting to %@ · unlocks on approval", command, host)
                                  : format("%@ is connecting to %@", command, host)
        }
        return request.locked ? format("%@ is requesting a signature · unlocks on approval", command)
                              : format("%@ is requesting a signature", command)
    }

    private var details: some View {
        card {
            row("Key") {
                Text(verbatim: "\(request.keyName) · \(request.keyAlgorithm)").truncationMode(.middle)
            }
            divider
            row("Fingerprint") {
                Text(verbatim: request.shortenedFingerprint).font(.system(size: 12, design: .monospaced))
                    .accessibilityLabel(request.fingerprint)
            }
            divider
            row("Destination Host") {
                if let host = request.verifiedHost {
                    Label {
                        Text(verbatim: host).truncationMode(.middle)
                    } icon: {
                        Image(systemName: "checkmark.shield").foregroundStyle(.green)
                    }
                    .accessibilityLabel(format("Verified host: %@", host))
                } else {
                    Text(verbatim: text("Unknown"))
                }
            }
            divider
            row("Request Source") {
                Text(verbatim: request.peer.chain.isEmpty ? text("Unknown") : request.peer.chain.joined(separator: " › "))
                    .font(.system(size: 12, design: .monospaced)).truncationMode(.middle)
            }
        }
        .privacySensitive()
    }

    private var durationPicker: some View {
        card {
            row("Approval Duration") {
                Picker(text("Approval Duration"), selection: Bindable(model).duration) {
                    ForEach(model.allowedDurations, id: \.self) { duration in
                        Text(verbatim: text(duration.label)).tag(duration)
                    }
                }
                .labelsHidden().pickerStyle(.menu).fixedSize()
                .accessibilityIdentifier("ssh-agent.duration")
            }
        }
    }

    private var touchIDStatus: some View {
        HStack(spacing: 12) {
            Image(systemName: "touchid").font(.system(size: 34))
                .foregroundStyle(.secondary).frame(width: 40, height: 40)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(verbatim: text("Place your finger on Touch ID"))
                    ProgressView().controlSize(.small).accessibilityHidden(true)
                }
                Button(text("Use Password…"), action: model.usePassword)
                    .font(.system(size: 12)).buttonStyle(.link)
                    .disabled(model.isAuthorized)
                    .accessibilityIdentifier("ssh-agent.use-password")
            }
        }
        .accessibilityIdentifier("ssh-agent.touch-id")
    }

    private var passwordRow: some View {
        let title = text(request.locked ? "Master Password" : "Login Password")
        let placeholder = text(request.locked ? "Enter the master password" : "Enter the Mac login password")
        return card {
            row(title, localizeLabel: false) {
                SecureField(title, text: Bindable(model).password, prompt: Text(verbatim: placeholder))
                    .textFieldStyle(.plain).multilineTextAlignment(.trailing).labelsHidden()
                    .textContentType(.password).focused($passwordFocused)
                    .disabled(model.isCheckingPassword)
                    .onSubmit(model.submitPassword)
                    .accessibilityIdentifier("ssh-agent.password")
                    .accessibilityHint(model.passwordRejected ? text("Password verification failed") : "")
            }
        }
        .overlay {
            if model.passwordRejected {
                RoundedRectangle(cornerRadius: 10).strokeBorder(.red, lineWidth: highContrast ? 2 : 1)
                    .allowsHitTesting(false)
            }
        }
        .onAppear { passwordFocused = true }
        .onChange(of: model.passwordRejected) { _, rejected in if rejected { passwordFocused = true } }
    }

    @ViewBuilder private var buttons: some View {
        HStack(spacing: 10) {
            switch model.phase {
            case .ask:
                countdownButton
                primaryButton(touchID: true, action: model.approve)
            case .touch:
                cancelButton
            case .password:
                cancelButton
                primaryButton(touchID: false, action: model.submitPassword)
                    .disabled(model.password.isEmpty || model.isCheckingPassword)
            case .done, .denied: EmptyView()
            }
        }
        .controlSize(.large)
    }

    private var cancelButton: some View {
        Button(text("Cancel"), action: model.cancelVerification)
            .disabled(model.isAuthorized)
            .accessibilityIdentifier("ssh-agent.cancel")
    }

    private func primaryButton(touchID: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 6) {
                if touchID { Image(systemName: "touchid").accessibilityHidden(true) }
                else if model.isCheckingPassword { ProgressView().controlSize(.small).accessibilityHidden(true) }
                Text(verbatim: text(approveLabel))
            }
        }
        .buttonStyle(.borderedProminent)
        .tint(.blue)
        .accessibilityIdentifier("ssh-agent.authorize")
    }

    @ViewBuilder private var countdownButton: some View {
        if reduceMotion {
            TimelineView(.periodic(from: .now, by: 1)) { _ in denyButton(model.countdown(reduceMotion: true)) }
        } else {
            TimelineView(.animation(minimumInterval: 1.0 / 30)) { _ in denyButton(model.countdown(reduceMotion: false)) }
        }
    }

    private func denyButton(_ countdown: MacSSHApprovalCountdown) -> some View {
        let background = Color.primary.opacity(highContrast ? 0.12 : 0.07)
            .mix(with: .red.opacity(highContrast ? 0.28 : 0.18), by: countdown.warning)
        let fill = Color.primary.opacity(highContrast ? 0.28 : 0.20)
            .mix(with: .red.opacity(highContrast ? 0.52 : 0.38), by: countdown.warning)
        return Button(action: model.deny) {
            Text(verbatim: reduceMotion ? format("Deny (%lld)", countdown.seconds) : text("Deny"))
                .padding(.horizontal, 12).frame(height: 28)
                .foregroundStyle(Color.primary.mix(with: .red, by: countdown.warning))
                .background {
                    GeometryReader { proxy in
                        ZStack(alignment: .leading) {
                            background
                            if !reduceMotion { fill.frame(width: proxy.size.width * countdown.fraction) }
                        }
                    }
                    .clipShape(.rect(cornerRadius: 7))
                }
                .overlay {
                    if highContrast {
                        RoundedRectangle(cornerRadius: 7).strokeBorder(Color(nsColor: .separatorColor))
                    }
                }
                .contentShape(.rect(cornerRadius: 7))
        }
        .buttonStyle(.plain)
        .accessibilityLabel(format("Deny, automatically denied in %lld seconds", countdown.seconds))
        .accessibilityIdentifier("ssh-agent.deny")
    }

    private func receipt(duration: MacSSHApprovalDuration?) -> some View {
        VStack(spacing: 10) {
            Image(systemName: duration == nil ? "xmark" : "checkmark")
                .font(.system(size: 25, weight: .semibold))
                .foregroundStyle(duration == nil ? Color.primary : .white)
                .frame(width: 56, height: 56)
                .background(duration == nil ? Color(nsColor: .quaternaryLabelColor) : .green, in: .circle)
                .accessibilityHidden(true)
            Text(verbatim: text(duration == nil ? "Denied" : "Approved"))
                .font(.system(size: 20, weight: .bold)).accessibilityAddTraits(.isHeader)
            Text(verbatim: receiptMessage(duration)).foregroundStyle(.secondary)
                .lineLimit(1).padding(.horizontal, 24)
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("ssh-agent.receipt")
    }

    private func receiptMessage(_ duration: MacSSHApprovalDuration?) -> String {
        switch duration {
        case .once: text("Only this time.")
        case .minutes15: format("“%@” won't need approval for 15 minutes.", appName)
        case .untilVaultLock: format("“%@” won't need approval until the vault locks.", appName)
        case nil: format("%@ received “permission denied”.", command)
        }
    }

    private func row<Value: View>(_ label: String, localizeLabel: Bool = true, @ViewBuilder value: () -> Value) -> some View {
        HStack(spacing: 12) {
            Text(verbatim: localizeLabel ? text(label) : label)
            Spacer(minLength: 0)
            value().lineLimit(1).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 12)
        .frame(height: 38)
    }

    private var divider: some View {
        Color(nsColor: .separatorColor).frame(height: 1)
            .padding(.horizontal, 12).padding(.bottom, -1)
            .accessibilityHidden(true)
    }

    private func card<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        VStack(spacing: 0, content: content)
            .background(Color(nsColor: .controlBackgroundColor), in: .rect(cornerRadius: 10))
            .overlay {
                RoundedRectangle(cornerRadius: 10).strokeBorder(Color(nsColor: .separatorColor), lineWidth: highContrast ? 1 : 0.5)
                    .allowsHitTesting(false)
            }
    }

    private func text(_ key: String) -> String { macSSHAgentText(key, locale: locale) }
    private func format(_ key: String, _ argument: String) -> String { macSSHAgentText(key, argument, locale: locale) }
    private func format(_ key: String, _ first: String, _ second: String) -> String { macSSHAgentText(key, first, second, locale: locale) }
    private func format(_ key: String, _ seconds: Int) -> String { macSSHAgentText(key, seconds, locale: locale) }
}
