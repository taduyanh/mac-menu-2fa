import SwiftUI

/// Shows chosen accounts as Google Authenticator export QR codes, so a phone
/// can scan them in. Read-only: nothing is removed from MenuAuth.
struct ExportView: View {
    @Binding var route: MenuPanel.Route
    @Environment(AccountStore.self) private var store

    @State private var selection: Set<UUID> = []
    /// One export URL per batch. Non-empty means the QR step is showing. Only
    /// the visible page is rendered to an image, so memory stays at one QR.
    @State private var urls: [String] = []
    @State private var qrImage: NSImage?
    @State private var skippedCount = 0
    @State private var page = 0
    @State private var isAuthenticating = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header

            if !store.gate.isUnlocked {
                lockedNotice
            } else if urls.isEmpty {
                selectionStep
            } else {
                qrStep
            }
        }
        .onAppear { selection = Set(store.accounts.map(\.id)) }
        // Idle-lock (or Lock now) must not leave secrets on screen.
        .onChange(of: store.gate.isUnlocked) { _, unlocked in
            if !unlocked { clearQR() }
        }
        .onDisappear { clearQR() }
    }

    // MARK: - Chrome

    private var header: some View {
        HStack {
            Button {
                if urls.isEmpty {
                    route = .settings
                } else {
                    clearQR()
                }
            } label: {
                Label("Back", systemImage: "chevron.left")
                    .font(.system(size: 12))
            }
            .buttonStyle(.plain)

            Spacer()
            Text("Export accounts").font(.system(size: 12, weight: .semibold))
            Spacer()
            Color.clear.frame(width: 44, height: 1)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private var lockedNotice: some View {
        VStack(spacing: 8) {
            Text("Unlock to export — the QR codes contain your secrets.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button {
                Task { await store.unlock() }
            } label: {
                Label("Unlock", systemImage: "touchid")
            }
            if let message = store.gate.lastErrorMessage {
                Text(message).font(.caption).foregroundStyle(.red)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(16)
    }

    // MARK: - Step 1: choose accounts

    private var selectionStep: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("\(selection.count) of \(store.accounts.count) selected")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("All") { selection = Set(store.accounts.map(\.id)) }
                Button("None") { selection = [] }
            }
            .buttonStyle(.plain)
            .font(.system(size: 11))
            .padding(.horizontal, 12)
            .padding(.bottom, 6)

            Divider()

            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(store.accounts) { account in
                        row(for: account)
                    }
                }
                .padding(.horizontal, 6)
                .padding(.vertical, 4)
            }
            .frame(maxHeight: 360)

            Divider()

            VStack(alignment: .leading, spacing: 8) {
                Text("Shows QR codes that contain these accounts' secrets. "
                    + "Nothing is removed from MenuAuth.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)

                if skippedCount > 0 {
                    Label("The selected accounts' secrets couldn't be read.",
                        systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }

                HStack {
                    Spacer()
                    Button("Show QR Code\(selection.count > MigrationEncoder.defaultBatchSize ? "s" : "")") {
                        generate()
                    }
                    .controlSize(.small)
                    .buttonStyle(.borderedProminent)
                    .disabled(selection.isEmpty || isAuthenticating)
                }
            }
            .padding(12)
        }
    }

    private func row(for account: Account) -> some View {
        let isSelected = selection.contains(account.id)
        return Button {
            if isSelected {
                selection.remove(account.id)
            } else {
                selection.insert(account.id)
            }
        } label: {
            HStack(spacing: 8) {
                Image(systemName: isSelected ? "checkmark.square.fill" : "square")
                    .foregroundStyle(isSelected ? Color.accentColor : .secondary)
                VStack(alignment: .leading, spacing: 1) {
                    Text(account.displayTitle)
                        .font(.system(size: 12, weight: .medium))
                        .lineLimit(1)
                    if !account.displaySubtitle.isEmpty {
                        Text(account.displaySubtitle)
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
    }

    // MARK: - Step 2: QR codes

    private var qrStep: some View {
        VStack(spacing: 10) {
            if let qrImage {
                // Natural size: the image is already a whole number of pixels
                // per module, so scaling it again would blur the edges.
                Image(nsImage: qrImage)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            }

            if urls.count > 1 {
                HStack(spacing: 14) {
                    Button { show(page - 1) } label: { Image(systemName: "chevron.left") }
                        .disabled(page == 0)
                    Text("QR \(page + 1) of \(urls.count)")
                        .font(.system(size: 12, weight: .medium))
                        .monospacedDigit()
                    Button { show(page + 1) } label: { Image(systemName: "chevron.right") }
                        .disabled(page == urls.count - 1)
                }
                .buttonStyle(.plain)
            }

            Text("On the new phone, in Google Authenticator: ⋯ → Transfer accounts → "
                + "Import accounts → Scan QR code"
                + (urls.count > 1 ? ", then scan each code in turn." : "."))
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)

            if skippedCount > 0 {
                Label("\(skippedCount) account\(skippedCount == 1 ? "" : "s") couldn't be read "
                    + "and \(skippedCount == 1 ? "was" : "were") left out.",
                    systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Button("Done") { route = .list }
                .controlSize(.small)
        }
        .padding(12)
        .frame(maxWidth: .infinity)
    }

    // MARK: - Actions

    /// Revealing every secret needs a fresh authentication, not just the
    /// session that happens to be open — see `BiometricGate.confirmPresence`.
    private func generate() {
        guard !isAuthenticating else { return }
        isAuthenticating = true
        Task {
            defer { isAuthenticating = false }
            guard await store.gate.confirmPresence(
                reason: "export your accounts as QR codes"
            ) else { return }

            let exported = store.accountsForExport(ids: selection)
            skippedCount = selection.count - exported.count
            urls = MigrationEncoder.urls(for: exported)
            if !urls.isEmpty { show(0) }
            store.gate.noteActivity()
        }
    }

    private func show(_ newPage: Int) {
        page = newPage
        qrImage = QRCodeImage.make(from: urls[newPage])
    }

    private func clearQR() {
        urls = []
        qrImage = nil
        skippedCount = 0
        page = 0
    }
}
