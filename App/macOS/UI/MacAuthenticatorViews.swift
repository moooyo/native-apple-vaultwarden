import SwiftUI
import DesignSystem
import Generators

@available(macOS 27.0, *)
struct MacAuthenticatorListView: View {
    let entries: [MacTOTPEntry]
    @Binding var selection: String?
    let onNewItem: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(.black.opacity(0.4))

            if entries.isEmpty {
                ContentUnavailableView(
                    "没有验证码",
                    systemImage: "clock",
                    description: Text("为登录条目设置验证器密钥后，动态验证码会显示在这里。")
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    ScrollView {
                        LazyVStack(spacing: 1) {
                            ForEach(entries) { entry in
                                MacAuthenticatorRow(
                                    entry: entry,
                                    date: context.date,
                                    isSelected: selection == entry.id
                                ) {
                                    selection = entry.id
                                }
                            }
                        }
                        .padding(.horizontal, 8)
                        .padding(.vertical, 6)
                    }
                }
            }
        }
        .background(MacOpenVaultStyle.list)
    }

    private var header: some View {
        HStack(spacing: 9) {
            Image(systemName: "chevron.left")
                .foregroundStyle(.white.opacity(0.72))
            Image(systemName: "chevron.right")
                .foregroundStyle(.white.opacity(0.28))
            Text("验证码")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(.white)
            Spacer()
            Button(action: onNewItem) {
                Image(systemName: "plus")
                    .font(.system(size: 12, weight: .semibold))
                    .frame(width: 27, height: 27)
            }
            .buttonStyle(.glassProminent)
            .help("新建带验证码的登录条目")
        }
        .padding(.horizontal, 14)
        .frame(height: 50)
    }
}

@available(macOS 27.0, *)
private struct MacAuthenticatorRow: View {
    let entry: MacTOTPEntry
    let date: Date
    let isSelected: Bool
    let action: () -> Void

    @State private var isHovering = false

    private var code: String {
        OTPRingMath.formatCode(TOTP.code(for: entry.configuration, at: date))
    }

    private var progress: Double {
        let seconds = TOTP.secondsRemaining(for: entry.configuration, at: date)
        return OTPRingMath.progress(secondsRemaining: seconds, period: entry.configuration.period)
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                BrandBadge(entry.cipher.name, diameter: 30)
                VStack(alignment: .leading, spacing: 1) {
                    Text(entry.cipher.name.nilIfBlank ?? "未命名条目")
                        .font(.system(size: 13.5, weight: .semibold))
                        .foregroundStyle(isSelected ? .white : .white.opacity(0.92))
                        .lineLimit(1)
                    Text(entry.account)
                        .font(.system(size: 11.5))
                        .foregroundStyle(isSelected ? .white.opacity(0.76) : .white.opacity(0.45))
                        .lineLimit(1)
                }
                Spacer(minLength: 5)
                Text(code)
                    .font(.system(size: 13, weight: .medium, design: .monospaced))
                    .tracking(0.8)
                    .monospacedDigit()
                    .foregroundStyle(isSelected ? .white : .white.opacity(0.86))
                CountdownRing(
                    progress: progress,
                    size: 14,
                    lineWidth: 2.2,
                    tint: isSelected ? .white : MacOpenVaultStyle.totp
                )
            }
            .padding(.horizontal, 9)
            .frame(minHeight: 44)
            .contentShape(Rectangle())
            .background {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(isSelected ? MacOpenVaultStyle.selected : (isHovering ? .white.opacity(0.06) : .clear))
            }
        }
        .buttonStyle(.plain)
        .onHover { isHovering = $0 }
        .accessibilityLabel("\(entry.cipher.name)，验证码 \(code)")
    }
}

@available(macOS 27.0, *)
struct MacAuthenticatorDetailView: View {
    let entry: MacTOTPEntry
    let onShowLinkedItem: () -> Void

    @State private var copiedMessage: String?
    @State private var toastID = UUID()

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let code = OTPRingMath.formatCode(TOTP.code(for: entry.configuration, at: context.date))
            let seconds = TOTP.secondsRemaining(for: entry.configuration, at: context.date)
            let progress = OTPRingMath.progress(
                secondsRemaining: seconds,
                period: entry.configuration.period
            )

            VStack(alignment: .leading, spacing: 0) {
                header(code: code)
                hero(code: code, progress: progress)
                    .padding(.top, 16)
                informationCard
                    .padding(.top, 11)
                Spacer(minLength: 24)
                footer
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 18)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .background(MacOpenVaultStyle.detail)
            .overlay(alignment: .bottom) {
                if let copiedMessage {
                    GlassToast(copiedMessage)
                        .padding(.bottom, 24)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
        }
    }

    private func header(code: String) -> some View {
        HStack(spacing: 13) {
            BrandBadge(entry.cipher.name, diameter: 50)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.cipher.name.nilIfBlank ?? "未命名条目")
                    .font(.system(size: 20, weight: .bold))
                    .foregroundStyle(.white)
                Text("验证码 · TOTP · \(entry.configuration.period) 秒周期")
                    .font(.system(size: 12))
                    .foregroundStyle(MacOpenVaultStyle.secondary)
            }
            Spacer()
            Button {
                copy(code.replacingOccurrences(of: " ", with: ""), message: "已拷贝验证码")
            } label: {
                Label("拷贝验证码", systemImage: "doc.on.doc")
                    .font(.system(size: 12.5, weight: .semibold))
                    .padding(.horizontal, 4)
                    .frame(height: 30)
            }
            .buttonStyle(.glassProminent)
        }
    }

    private func hero(code: String, progress: Double) -> some View {
        HStack(spacing: 18) {
            Text(code)
                .font(.system(size: 38, weight: .medium, design: .monospaced))
                .tracking(3.5)
                .monospacedDigit()
                .foregroundStyle(.white.opacity(0.97))
                .contentTransition(.numericText())
            CountdownRing(progress: progress, size: 30, lineWidth: 2.6, tint: MacOpenVaultStyle.totp)
                .shadow(color: MacOpenVaultStyle.totp.opacity(0.55), radius: 7)
        }
        .frame(maxWidth: .infinity, minHeight: 112)
        .background {
            RoundedRectangle(cornerRadius: CornerRadius.macCard, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [.white.opacity(0.10), .white.opacity(0.04)],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )
                .overlay(alignment: .bottom) {
                    Ellipse()
                        .fill(MacOpenVaultStyle.totp.opacity(0.08))
                        .frame(height: 54)
                        .blur(radius: 20)
                        .clipped()
                }
        }
        .overlay {
            RoundedRectangle(cornerRadius: CornerRadius.macCard, style: .continuous)
                .stroke(.white.opacity(0.13), lineWidth: 0.5)
        }
        .shadow(color: .black.opacity(0.25), radius: 13, y: 8)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("当前验证码 \(code)")
    }

    private var informationCard: some View {
        OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 0) {
            VStack(spacing: 0) {
                valueRow("账户", value: entry.account, copyValue: entry.account)
                Divider().overlay(MacOpenVaultStyle.hairline).padding(.leading, 15)
                if let website = entry.website {
                    valueRow("网站", value: website, copyValue: website, isLink: true)
                    Divider().overlay(MacOpenVaultStyle.hairline).padding(.leading, 15)
                }
                Button(action: onShowLinkedItem) {
                    HStack {
                        Text("已关联登录项")
                        Spacer()
                        Text(entry.cipher.name.nilIfBlank ?? "未命名条目")
                            .foregroundStyle(.white.opacity(0.62))
                        Image(systemName: "chevron.right")
                            .font(.system(size: 9, weight: .semibold))
                            .foregroundStyle(.white.opacity(0.34))
                    }
                    .font(.system(size: 13.5))
                    .foregroundStyle(.white.opacity(0.90))
                    .padding(.horizontal, 15)
                    .frame(minHeight: 44)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .overlay {
            RoundedRectangle(cornerRadius: CornerRadius.macCard, style: .continuous)
                .stroke(.white.opacity(0.07), lineWidth: 0.5)
        }
    }

    private func valueRow(_ label: String, value: String, copyValue: String, isLink: Bool = false) -> some View {
        HStack {
            Text(label)
            Spacer()
            Text(value)
                .foregroundStyle(isLink ? Color(red: 121 / 255, green: 186 / 255, blue: 1) : .white.opacity(0.62))
                .lineLimit(1)
                .truncationMode(.middle)
            Button {
                copy(copyValue, message: "已拷贝\(label)")
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .foregroundStyle(MacOpenVaultStyle.selectedBlue)
            .help("拷贝\(label)")
        }
        .font(.system(size: 13.5))
        .foregroundStyle(.white.opacity(0.90))
        .padding(.horizontal, 15)
        .frame(minHeight: 44)
    }

    private var footer: some View {
        HStack {
            Text("验证码在本机离线生成 · 密钥已端到端加密")
            Spacer()
            Text("每 \(entry.configuration.period) 秒自动轮换")
        }
        .font(.system(size: 11))
        .foregroundStyle(.white.opacity(0.38))
        .padding(.top, 10)
    }

    private func copy(_ value: String, message: String) {
        MacClipboard.copy(value)
        let id = UUID()
        toastID = id
        withAnimation(.snappy(duration: 0.25)) { copiedMessage = message }
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(1.6))
            guard toastID == id else { return }
            withAnimation(.easeOut(duration: 0.2)) { copiedMessage = nil }
        }
    }
}
