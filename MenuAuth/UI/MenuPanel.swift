import AppKit
import SwiftUI

/// The menu bar panel: the whole app, apart from the icon it hangs from.
struct MenuPanel: View {
    enum Route: Equatable {
        case list
        case importing
        case settings
        case exporting
    }

    @Environment(AccountStore.self) private var store
    @Environment(AppSettings.self) private var settings
    @Environment(ImportSession.self) private var importSession

    @State private var route: Route = .list
    @State private var copiedAccountID: UUID?
    @State private var copyResetTask: Task<Void, Never>?
    /// Natural height of the account rows. A bare `ScrollView` inside a
    /// `MenuBarExtra` window has no intrinsic height and collapses to a sliver
    /// (clipping rows mid-way), so the height is measured and set explicitly.
    @State private var listContentHeight: CGFloat = 0

    private static let maxListHeight: CGFloat = 520
    private static let estimatedRowHeight: CGFloat = 66

    var body: some View {
        VStack(spacing: 0) {
            switch route {
            case .list:
                accountList
            case .importing:
                ImportView(route: $route)
            case .settings:
                SettingsView(route: $route)
            case .exporting:
                ExportView(route: $route)
            }
        }
        .frame(width: 340)
        // The hinge the footprint design hangs on: the clock only runs while
        // this view is on screen.
        .onAppear {
            store.panelDidAppear()
            // Reopening mid-import drops the user back where they were, so
            // going to swipe to the next export QR feels continuous.
            if importSession.isInProgress { route = .importing }
        }
        .onDisappear {
            store.panelDidDisappear()
            route = importSession.isInProgress ? .importing : .list
            copyResetTask?.cancel()
            copiedAccountID = nil
        }
        .onChange(of: settings.idleTimeout) { store.gate.idleTimeout = settings.idleTimeout }
    }

    // MARK: - Account list

    @ViewBuilder
    private var accountList: some View {
        @Bindable var store = store

        if store.isEmpty {
            emptyState
        } else {
            if store.accounts.count > 5 {
                searchField
                Divider()
            }

            ScrollView {
                LazyVStack(spacing: 2) {
                    ForEach(store.filteredAccounts) { account in
                        AccountRow(
                            account: account,
                            code: store.codes[account.id],
                            secondsRemaining: store.secondsRemaining(for: account),
                            isLocked: !store.gate.isUnlocked,
                            isUnreadable: store.unreadableAccountIDs.contains(account.id),
                            isCopied: copiedAccountID == account.id,
                            onCopy: { copy(account) }
                        )
                        .contextMenu {
                            Button("Remove \(account.displayTitle)…", role: .destructive) {
                                store.delete(account)
                            }
                        }
                    }
                }
                .padding(.horizontal, 6)
                .padding(.vertical, 6)
                .onGeometryChange(for: CGFloat.self) { $0.size.height } action: {
                    listContentHeight = $0
                }
            }
            .frame(height: listHeight)
            // Deliberately attached here rather than to the whole panel:
            // reading `clock.tick` creates a view dependency on it, so keeping
            // it inside the list branch means the import and settings screens
            // are not re-rendered once a second for a clock they never show.
            .onChange(of: store.clock.tick) { store.refreshCodes() }

            if store.filteredAccounts.isEmpty {
                Text("No accounts match “\(store.searchText)”.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.bottom, 10)
            }
        }

        if !store.gate.isUnlocked {
            Divider()
            unlockBar
        }

        if let message = store.loadErrorMessage {
            Divider()
            Text(message)
                .font(.caption)
                .foregroundStyle(.orange)
                .padding(8)
        }

        Divider()
        footer
    }

    private var listHeight: CGFloat {
        let measured = listContentHeight > 0
            ? listContentHeight
            : CGFloat(store.filteredAccounts.count) * Self.estimatedRowHeight + 12
        return min(max(measured, 0), Self.maxListHeight)
    }

    private var searchField: some View {
        @Bindable var store = store
        return HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
                .font(.system(size: 11))
            TextField("Search", text: $store.searchText)
                .textFieldStyle(.plain)
                .font(.system(size: 12))
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 30, weight: .light))
                .foregroundStyle(.secondary)
            Text("No accounts yet")
                .font(.system(size: 13, weight: .semibold))
            Text("In Google Authenticator, tap ⋯ → Transfer accounts → Export accounts, "
                + "then scan the QR code here.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            Button("Add accounts…") { route = .importing }
                .controlSize(.small)
                .padding(.top, 2)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 24)
    }

    private var unlockBar: some View {
        VStack(spacing: 6) {
            Button {
                Task { await store.unlock() }
            } label: {
                Label("Unlock to show codes", systemImage: "touchid")
                    .font(.system(size: 12, weight: .medium))
                    .frame(maxWidth: .infinity)
            }
            .controlSize(.regular)

            if let message = store.gate.lastErrorMessage {
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
        .padding(10)
    }

    private var footer: some View {
        HStack(spacing: 4) {
            Button {
                route = .importing
            } label: {
                Label("Add", systemImage: "plus")
                    .font(.system(size: 11))
            }
            .buttonStyle(.plain)
            .help("Add accounts")

            Spacer()

            if store.gate.isUnlocked, store.gate.enforcement != .unavailable {
                Button {
                    store.lock()
                } label: {
                    Image(systemName: "lock")
                }
                .buttonStyle(.plain)
                .help("Lock now")
            }

            Button {
                route = .settings
            } label: {
                Image(systemName: "gearshape")
            }
            .buttonStyle(.plain)
            .help("Settings")

            Button {
                NSApplication.shared.terminate(nil)
            } label: {
                Image(systemName: "power")
            }
            .buttonStyle(.plain)
            .help("Quit MenuAuth")
        }
        .font(.system(size: 12))
        .foregroundStyle(.secondary)
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    // MARK: - Actions

    private func copy(_ account: Account) {
        guard let code = store.codes[account.id] else { return }
        Pasteboard.copyCode(code)
        store.gate.noteActivity()

        copiedAccountID = account.id
        copyResetTask?.cancel()
        copyResetTask = Task {
            try? await Task.sleep(for: .milliseconds(1200))
            guard !Task.isCancelled else { return }
            copiedAccountID = nil
        }
    }
}
