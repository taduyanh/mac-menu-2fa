import SwiftUI

/// One account, laid out like the Google Authenticator row: issuer, account
/// name, the code itself, and the countdown.
struct AccountRow: View {
    let account: Account
    let code: String?
    let secondsRemaining: Int
    let isLocked: Bool
    let isUnreadable: Bool
    let isCopied: Bool
    let onCopy: () -> Void

    @State private var isHovering = false

    var body: some View {
        Button(action: onCopy) {
            HStack(alignment: .center, spacing: 10) {
                VStack(alignment: .leading, spacing: 1) {
                    Text(account.displayTitle)
                        .font(.system(size: 12, weight: .semibold))
                        .lineLimit(1)

                    if !account.displaySubtitle.isEmpty {
                        Text(account.displaySubtitle)
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }

                    Text(displayedCode)
                        .font(.system(size: 21, weight: .regular, design: .rounded))
                        .monospacedDigit()
                        .foregroundStyle(codeColor)
                        .padding(.top, 1)
                }

                Spacer(minLength: 4)

                if isCopied {
                    Label("Copied", systemImage: "checkmark")
                        .labelStyle(.iconOnly)
                        .font(.system(size: 13, weight: .bold))
                        .foregroundStyle(.green)
                        .frame(width: 22, height: 22)
                        .transition(.opacity)
                } else if isUnreadable {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .frame(width: 22, height: 22)
                        .help("This account's secret couldn't be read from the Keychain.")
                } else if !isLocked {
                    CountdownRing(secondsRemaining: secondsRemaining, period: account.period)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .contentShape(.rect(cornerRadius: 7))
            .background {
                RoundedRectangle(cornerRadius: 7)
                    .fill(isHovering ? Color.primary.opacity(0.07) : .clear)
            }
        }
        .buttonStyle(.plain)
        .disabled(code == nil)
        .onHover { isHovering = $0 }
        .help(code == nil ? "" : "Click to copy")
        .accessibilityLabel(accessibilityDescription)
    }

    /// Grouped the way the phone app groups them, so the digits are readable at
    /// a glance: 3+3 for six digits, 4+4 for eight.
    private var displayedCode: String {
        guard let code else {
            return isLocked ? String(repeating: "•", count: 3) + " " + String(repeating: "•", count: 3)
                : "······"
        }
        let midpoint = code.count / 2
        guard code.count % 2 == 0, midpoint > 0 else { return code }
        let index = code.index(code.startIndex, offsetBy: midpoint)
        return "\(code[..<index]) \(code[index...])"
    }

    private var codeColor: Color {
        if code == nil { return .secondary }
        return secondsRemaining <= 5 ? .red : .primary
    }

    private var accessibilityDescription: String {
        guard let code else { return "\(account.displayTitle), locked" }
        return "\(account.displayTitle), code \(code.map(String.init).joined(separator: " ")), "
            + "\(secondsRemaining) seconds remaining"
    }
}
