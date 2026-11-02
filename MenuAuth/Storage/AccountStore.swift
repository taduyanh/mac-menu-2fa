import Foundation
import Observation

/// Result of folding a scanned export into the existing account list.
nonisolated struct ImportSummary: Sendable, Equatable {
    var added: Int
    var updated: Int
    var skipped: Int
    var failed: Int

    var isEmpty: Bool { added == 0 && updated == 0 }

    var description: String {
        var parts: [String] = []
        if added > 0 { parts.append("\(added) added") }
        if updated > 0 { parts.append("\(updated) updated") }
        if skipped > 0 { parts.append("\(skipped) skipped") }
        if failed > 0 { parts.append("\(failed) failed") }
        return parts.isEmpty ? "Nothing to import" : parts.joined(separator: ", ")
    }
}

/// The app's source of truth: the account list, the currently displayed codes,
/// and the rules for when a code is recomputed.
@Observable
final class AccountStore {
    private(set) var accounts: [Account] = []
    /// Rendered codes, keyed by account. Absent while locked.
    private(set) var codes: [UUID: String] = [:]
    private(set) var loadErrorMessage: String?
    /// Accounts whose secret could not be read even after unlocking.
    private(set) var unreadableAccountIDs: Set<UUID> = []

    var searchText = ""

    let clock: CodeClock
    let vault: SecretVault
    let gate: BiometricGate

    private let metadata: AccountMetadataStore
    /// The time step each account's displayed code was generated for. A code is
    /// only recomputed when this changes — once per period, not once per tick.
    @ObservationIgnored private var renderedCounters: [UUID: UInt64] = [:]

    /// How many TOTP codes have actually been computed. Exists so the "one HMAC
    /// per account per period" claim is an assertion in the test suite rather
    /// than a comment.
    @ObservationIgnored private(set) var codeComputationCount = 0

    init(
        metadata: AccountMetadataStore,
        vault: SecretVault,
        gate: BiometricGate,
        clock: CodeClock = CodeClock()
    ) {
        self.metadata = metadata
        self.vault = vault
        self.gate = gate
        self.clock = clock

        gate.onLock = { [weak self] in
            self?.handleLock()
        }
        reload()
    }

    var filteredAccounts: [Account] {
        guard !searchText.isEmpty else { return accounts }
        return accounts.filter { $0.matches(searchText: searchText) }
    }

    var isEmpty: Bool { accounts.isEmpty }

    // MARK: - Panel lifecycle
    //
    // These are the hinges the whole footprint design hangs on: nothing
    // periodic runs unless the panel is on screen.

    func panelDidAppear() {
        clock.bindToAppActivation()
        clock.start()
        gate.noteActivity()
        if gate.isUnlocked {
            loadSecretsIntoCache()
        }
        refreshCodes(force: true)
    }

    func panelDidDisappear() {
        clock.stop()
    }

    // MARK: - Codes

    /// Recomputes only the codes whose time step has rolled over.
    ///
    /// Called on every 1 Hz tick, so the early-exit is what keeps the steady
    /// state at roughly one HMAC per account per 30 seconds.
    func refreshCodes(force: Bool = false) {
        guard gate.isUnlocked else {
            if !codes.isEmpty { codes.removeAll() }
            return
        }

        let now = clock.tick
        for account in accounts {
            let counter = TOTP.counter(at: now, period: account.period)
            guard force || renderedCounters[account.id] != counter else { continue }
            guard let secret = vault.cachedSecret(for: account.id) else {
                codes.removeValue(forKey: account.id)
                continue
            }
            renderedCounters[account.id] = counter
            codeComputationCount += 1
            codes[account.id] = TOTP.code(
                secret: secret,
                counter: counter,
                digits: account.digits,
                algorithm: account.algorithm
            )
        }
    }

    func secondsRemaining(for account: Account) -> Int {
        TOTP.secondsRemaining(at: clock.tick, period: account.period)
    }

    // MARK: - Unlocking

    @discardableResult
    func unlock() async -> Bool {
        guard await gate.unlock() else { return false }
        loadSecretsIntoCache()
        refreshCodes(force: true)
        return true
    }

    func lock() {
        gate.lock()
    }

    private func handleLock() {
        vault.clearCache()
        codes.removeAll()
        renderedCounters.removeAll()
    }

    /// Opens the vault. One Keychain access covers every account, so the user
    /// sees at most one authorisation prompt regardless of how many they store.
    private func loadSecretsIntoCache() {
        do {
            try vault.open(
                context: gate.authenticatedContext,
                knownAccountIDs: accounts.map(\.id)
            )
            unreadableAccountIDs = Set(vault.missingSecretIDs(from: accounts.map(\.id)))
            loadErrorMessage = nil
        } catch {
            loadErrorMessage = error.localizedDescription
            unreadableAccountIDs = Set(accounts.map(\.id))
        }
    }

    // MARK: - Persistence

    func reload() {
        do {
            accounts = try metadata.load()
            loadErrorMessage = nil
        } catch {
            accounts = []
            loadErrorMessage = error.localizedDescription
        }
    }

    private func persist() {
        do {
            try metadata.save(accounts)
            loadErrorMessage = nil
        } catch {
            loadErrorMessage = error.localizedDescription
        }
    }

    // MARK: - Mutating the account list

    /// Folds scanned accounts in, replacing the secret of anything already
    /// present rather than creating a second row for it.
    @discardableResult
    func importAccounts(_ imported: [ImportedAccount], skipped: Int = 0) -> ImportSummary {
        // Writing opens the vault, which loads every secret into memory. Doing
        // that while locked would leave them resident with no re-lock timer to
        // clear them, so callers unlock first (one prompt, reused here).
        guard gate.isUnlocked else {
            loadErrorMessage = "Unlock MenuAuth to import accounts."
            return ImportSummary(added: 0, updated: 0, skipped: skipped, failed: imported.count)
        }
        var summary = ImportSummary(added: 0, updated: 0, skipped: skipped, failed: 0)
        var byKey = Dictionary(
            accounts.map { ($0.dedupeKey, $0) },
            uniquingKeysWith: { first, _ in first }
        )

        // Secrets are collected and written in a single pass, so an import
        // touches the Keychain and the encrypted store once rather than once
        // per account.
        var secrets: [UUID: Data] = [:]
        for entry in imported {
            let existing = byKey[entry.dedupeKey]
            let id = existing?.id ?? UUID()
            secrets[id] = entry.secret

            if let existing {
                let updated = entry.account(id: existing.id, sortIndex: existing.sortIndex)
                if let index = accounts.firstIndex(where: { $0.id == existing.id }) {
                    accounts[index] = updated
                }
                byKey[entry.dedupeKey] = updated
                summary.updated += 1
            } else {
                let account = entry.account(id: id, sortIndex: accounts.count)
                accounts.append(account)
                byKey[entry.dedupeKey] = account
                summary.added += 1
            }
            renderedCounters.removeValue(forKey: id)
        }

        do {
            try vault.store(secrets, context: gate.authenticatedContext)
        } catch {
            // Nothing was written, so drop the in-memory changes rather than
            // leaving rows that have no secret behind them.
            loadErrorMessage = error.localizedDescription
            reload()
            return ImportSummary(added: 0, updated: 0, skipped: skipped, failed: secrets.count)
        }

        persist()
        refreshCodes(force: true)
        return summary
    }

    /// How many of these would replace the secret of an account already stored.
    ///
    /// A QR code is untrusted input: one crafted with the same issuer and name
    /// as a real account would, on import, swap that account's secret for the
    /// attacker's and leave the user locked out of it. Callers use this to
    /// refuse to import such a batch without an explicit confirmation.
    func overwriteCount(for imported: [ImportedAccount]) -> Int {
        let existing = Set(accounts.map(\.dedupeKey))
        return imported.filter { existing.contains($0.dedupeKey) }.count
    }

    /// The chosen accounts with their secrets, in list order, ready for
    /// `MigrationEncoder`. Empty while locked, and skips any account whose
    /// secret couldn't be read. Read-only: exporting never changes the store.
    func accountsForExport(ids: Set<UUID>) -> [ImportedAccount] {
        guard gate.isUnlocked else { return [] }
        return accounts.compactMap { account in
            guard ids.contains(account.id),
                  let secret = vault.cachedSecret(for: account.id) else { return nil }
            return ImportedAccount(
                issuer: account.issuer,
                name: account.name,
                secret: secret,
                digits: account.digits,
                algorithm: account.algorithm,
                period: account.period
            )
        }
    }

    /// Requires an unlocked gate, for the same reason as `importAccounts`. The
    /// account stays listed if its secret could not be removed, so the user is
    /// never shown it as gone while the secret is still on disk.
    func delete(_ account: Account) {
        guard gate.isUnlocked else {
            loadErrorMessage = "Unlock MenuAuth to remove accounts."
            return
        }
        do {
            try vault.delete(id: account.id)
        } catch {
            loadErrorMessage = error.localizedDescription
            return
        }
        loadErrorMessage = nil
        accounts.removeAll { $0.id == account.id }
        codes.removeValue(forKey: account.id)
        renderedCounters.removeValue(forKey: account.id)
        unreadableAccountIDs.remove(account.id)
        reindex()
        persist()
    }

    func deleteAll() {
        // Not `try?`: if the secrets could not be removed the user must be told,
        // rather than shown an empty list while the data is still on disk.
        do {
            try vault.deleteAll()
            loadErrorMessage = nil
        } catch {
            loadErrorMessage = error.localizedDescription
        }
        accounts.removeAll()
        codes.removeAll()
        renderedCounters.removeAll()
        unreadableAccountIDs.removeAll()
        persist()
    }

    private func reindex() {
        for index in accounts.indices {
            accounts[index].sortIndex = index
        }
    }
}
