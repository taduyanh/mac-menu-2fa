import SwiftUI

struct SettingsView: View {
    @Binding var route: MenuPanel.Route
    @Environment(AccountStore.self) private var store
    @Environment(AppSettings.self) private var settings

    @State private var loginItemMessage: String?
    @State private var launchAtLogin = false
    @State private var isConfirmingRemoveAll = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header

            VStack(alignment: .leading, spacing: 14) {
                securitySection
                Divider()
                behaviourSection
                Divider()
                dangerSection
            }
            .padding(12)
        }
        .onAppear { launchAtLogin = settings.launchesAtLogin }
    }

    private var header: some View {
        HStack {
            Button {
                route = .list
            } label: {
                Label("Back", systemImage: "chevron.left")
                    .font(.system(size: 12))
            }
            .buttonStyle(.plain)

            Spacer()
            Text("Settings").font(.system(size: 12, weight: .semibold))
            Spacer()
            Color.clear.frame(width: 44, height: 1)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    /// States plainly what protection this build actually achieved. The app
    /// deliberately does not claim a Keychain-enforced gate it could not apply.
    private var securitySection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Security", systemImage: "lock.shield")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.secondary)

            Text(store.gate.enforcement.summary)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if store.gate.enforcement == .appEnforced {
                Text("For a Keychain-enforced gate, sign MenuAuth with an Apple Developer "
                    + "team in Xcode and rebuild.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if store.gate.enforcement != .unavailable {
                HStack {
                    Text("Lock after").font(.system(size: 12))
                    Spacer()
                    Picker("", selection: Binding(
                        get: { settings.idleTimeout },
                        set: { settings.idleTimeout = $0 }
                    )) {
                        ForEach(AppSettings.idleTimeoutChoices, id: \.self) { value in
                            Text(AppSettings.describeTimeout(value)).tag(value)
                        }
                    }
                    .labelsHidden()
                    .controlSize(.small)
                    .frame(width: 90)
                }
            }
        }
    }

    private var behaviourSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Toggle("Launch at login", isOn: Binding(
                get: { launchAtLogin },
                set: { newValue in
                    loginItemMessage = settings.setLaunchAtLogin(newValue)
                    launchAtLogin = settings.launchesAtLogin
                }
            ))
            .font(.system(size: 12))
            .controlSize(.small)

            if let loginItemMessage {
                Text(loginItemMessage)
                    .font(.caption2)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// The confirmation is drawn inline rather than with `.confirmationDialog`.
    ///
    /// A system dialog presented from a `MenuBarExtra` panel takes focus away
    /// from that panel, which dismisses it and tears down this view — taking the
    /// `@State` driving the dialog with it, so the confirm button did nothing.
    /// Keeping the confirmation inside the panel's own hierarchy avoids that
    /// entirely.
    private var dangerSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("\(store.accounts.count) account\(store.accounts.count == 1 ? "" : "s") stored")
                .font(.caption)
                .foregroundStyle(.secondary)

            if isConfirmingRemoveAll {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Remove all \(store.accounts.count) accounts?")
                        .font(.system(size: 12, weight: .semibold))
                    Text("This deletes every secret MenuAuth has stored. Make sure your "
                        + "phone still has them before continuing.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)

                    HStack(spacing: 8) {
                        Button("Cancel") { isConfirmingRemoveAll = false }
                            .controlSize(.small)
                        Button("Remove All", role: .destructive) {
                            // Same rule as removing a single account: no
                            // destructive change without authenticating.
                            Task {
                                guard await store.unlock() else { return }
                                store.deleteAll()
                                isConfirmingRemoveAll = false
                                route = .list
                            }
                        }
                        .controlSize(.small)
                        .buttonStyle(.borderedProminent)
                        .tint(.red)
                    }
                }
                .padding(10)
                .background {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(.red.opacity(0.10))
                }
            } else {
                HStack(spacing: 8) {
                    Button("Export Accounts…") { route = .exporting }
                        .controlSize(.small)
                        .disabled(store.isEmpty)
                    Button("Remove All Accounts…", role: .destructive) {
                        isConfirmingRemoveAll = true
                    }
                    .controlSize(.small)
                    .disabled(store.isEmpty)
                }
            }
        }
    }
}
