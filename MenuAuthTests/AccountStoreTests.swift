import Foundation
import Testing

@testable import MenuAuth

/// Builds a store wired to a throwaway metadata file and its own Keychain
/// service, with the gate set to `.unavailable` so nothing prompts.
@MainActor
private struct Harness {
    let store: AccountStore
    let vault: SecretVault
    let metadata: AccountMetadataStore
    let directory: URL
    let service: String

    init(service: String = "com.anhtd.MenuAuth.tests.store-\(UUID().uuidString)") {
        self.service = service
        directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("MenuAuthTests-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        metadata = AccountMetadataStore(
            fileURL: directory.appendingPathComponent("accounts.json")
        )
        // A per-test secrets file, so tests never touch the real app's store.
        vault = SecretVault(
            service: service,
            secretsFileURL: directory.appendingPathComponent("secrets.dat")
        )
        store = AccountStore(
            metadata: metadata,
            vault: vault,
            gate: BiometricGate(enforcement: .unavailable)
        )
    }

    var secretsFileURL: URL { directory.appendingPathComponent("secrets.dat") }

    func tearDown() {
        try? vault.deleteAll()
        try? KeychainStore(
            service: service,
            usesDataProtectionKeychain: KeychainAvailability.shared.usesDataProtectionKeychain
        ).deleteAll()
        try? FileManager.default.removeItem(at: directory)
    }

    /// Freezes time so code generation is deterministic.
    func setTime(_ date: Date) {
        store.clock.nowProvider = { date }
        store.clock.start()
        store.clock.stop()
    }
}

private let aliceSecret = Data("Hello!".utf8) + Data([0xde, 0xad, 0xbe, 0xef])

@Suite("Account store", .serialized)
@MainActor
struct AccountStoreTests {
    @Test("Importing adds accounts, secrets and metadata")
    func importAddsEverything() throws {
        let harness = Harness()
        defer { harness.tearDown() }

        let summary = harness.store.importAccounts([
            ImportedAccount(issuer: "Example", name: "alice@google.com", secret: aliceSecret),
            ImportedAccount(issuer: "GitHub", name: "anhtd", secret: Data("second".utf8)),
        ])

        #expect(summary == ImportSummary(added: 2, updated: 0, skipped: 0, failed: 0))
        #expect(harness.store.accounts.count == 2)

        // Metadata reached disk...
        let reloaded = try harness.metadata.load()
        #expect(reloaded.count == 2)
        #expect(reloaded.map(\.issuer) == ["Example", "GitHub"])

        // ...and the secrets reached the Keychain.
        for account in harness.store.accounts {
            #expect(harness.vault.hasSecret(for: account.id))
        }
    }

    /// The file the panel reads while locked must never contain key material.
    @Test("The metadata file contains no secret")
    func metadataFileHoldsNoSecret() throws {
        let harness = Harness()
        defer { harness.tearDown() }

        harness.store.importAccounts([
            ImportedAccount(issuer: "Example", name: "alice@google.com", secret: aliceSecret)
        ])

        let raw = try Data(contentsOf: harness.metadata.fileURL)
        let text = String(decoding: raw, as: UTF8.self)

        #expect(text.contains("Example"))
        #expect(!text.contains("Hello!"))
        #expect(!text.lowercased().contains("secret"))
        #expect(!raw.contains(aliceSecret))
    }

    /// Rescanning an export the user already imported should refresh it, not
    /// leave two rows with the same name.
    @Test("Re-importing updates in place instead of duplicating")
    func reimportUpdates() {
        let harness = Harness()
        defer { harness.tearDown() }

        harness.store.importAccounts([
            ImportedAccount(issuer: "Example", name: "alice@google.com", secret: Data("old".utf8))
        ])
        let originalID = harness.store.accounts.first?.id

        let summary = harness.store.importAccounts([
            ImportedAccount(issuer: "Example", name: "alice@google.com", secret: aliceSecret)
        ])

        #expect(summary == ImportSummary(added: 0, updated: 1, skipped: 0, failed: 0))
        #expect(harness.store.accounts.count == 1)
        #expect(harness.store.accounts.first?.id == originalID)
        #expect(harness.vault.cachedSecret(for: originalID!) == aliceSecret)
    }

    @Test("Generated codes match the RFC vector for the imported secret")
    func generatesCorrectCodes() {
        let harness = Harness()
        defer { harness.tearDown() }

        harness.store.importAccounts([
            ImportedAccount(issuer: "Example", name: "alice@google.com", secret: aliceSecret)
        ])
        harness.setTime(Date(timeIntervalSince1970: 0))
        harness.store.refreshCodes(force: true)

        let id = harness.store.accounts[0].id
        #expect(harness.store.codes[id] == "282760")
    }

    /// The central performance claim: the 1 Hz tick must not translate into
    /// 1 Hz of crypto. Thirty ticks inside one time step must produce exactly
    /// one computation per account.
    @Test("A code is computed once per period, not once per tick")
    func recomputesOncePerPeriod() {
        let harness = Harness()
        defer { harness.tearDown() }

        harness.store.importAccounts([
            ImportedAccount(issuer: "A", name: "a", secret: aliceSecret),
            ImportedAccount(issuer: "B", name: "b", secret: Data("another-secret".utf8)),
        ])

        // 1_699_999_980 is exactly divisible by 30, so the whole window
        // base..<base+30 sits inside a single time step.
        let base = 1_699_999_980.0
        #expect(base.truncatingRemainder(dividingBy: 30) == 0)

        harness.setTime(Date(timeIntervalSince1970: base))
        let beforeFirst = harness.store.codeComputationCount
        harness.store.refreshCodes(force: true)

        // A forced refresh costs exactly one computation per account.
        let baseline = harness.store.codeComputationCount
        #expect(baseline == beforeFirst + 2)

        // Twenty-nine more ticks inside the same step must cost nothing.
        for offset in 1..<30 {
            harness.setTime(Date(timeIntervalSince1970: base + Double(offset)))
            harness.store.refreshCodes()
        }
        #expect(harness.store.codeComputationCount == baseline)

        // Crossing the boundary recomputes exactly once more per account.
        harness.setTime(Date(timeIntervalSince1970: base + 30))
        harness.store.refreshCodes()
        #expect(harness.store.codeComputationCount == baseline + 2)
    }

    @Test("Codes change when the time step rolls over")
    func codesChangeAtBoundary() {
        let harness = Harness()
        defer { harness.tearDown() }

        harness.store.importAccounts([
            ImportedAccount(issuer: "Example", name: "alice@google.com", secret: aliceSecret)
        ])
        let id = harness.store.accounts[0].id

        harness.setTime(Date(timeIntervalSince1970: 0))
        harness.store.refreshCodes(force: true)
        let first = harness.store.codes[id]

        harness.setTime(Date(timeIntervalSince1970: 29))
        harness.store.refreshCodes()
        #expect(harness.store.codes[id] == first)

        harness.setTime(Date(timeIntervalSince1970: 30))
        harness.store.refreshCodes()
        #expect(harness.store.codes[id] != first)
    }

    @Test("Locking clears both the codes and the cached secrets")
    func lockingClearsPlaintext() {
        let harness = Harness()
        defer { harness.tearDown() }

        harness.store.importAccounts([
            ImportedAccount(issuer: "Example", name: "alice@google.com", secret: aliceSecret)
        ])
        harness.setTime(Date(timeIntervalSince1970: 0))
        harness.store.refreshCodes(force: true)
        let id = harness.store.accounts[0].id
        #expect(harness.store.codes[id] != nil)

        harness.vault.clearCache()

        #expect(harness.vault.cachedSecret(for: id) == nil)
    }

    @Test("Deleting removes the row, its code and its secret")
    func deleteRemovesEverything() {
        let harness = Harness()
        defer { harness.tearDown() }

        harness.store.importAccounts([
            ImportedAccount(issuer: "A", name: "a", secret: aliceSecret),
            ImportedAccount(issuer: "B", name: "b", secret: Data("second".utf8)),
        ])
        let target = harness.store.accounts[0]
        harness.store.delete(target)

        #expect(harness.store.accounts.count == 1)
        #expect(harness.store.codes[target.id] == nil)
        #expect(!harness.vault.hasSecret(for: target.id))
        // Remaining rows are re-indexed so ordering stays contiguous.
        #expect(harness.store.accounts[0].sortIndex == 0)
    }

    @Test("Removing all accounts empties both stores")
    func deleteAllEmptiesEverything() throws {
        let harness = Harness()
        defer { harness.tearDown() }

        harness.store.importAccounts((0..<4).map {
            ImportedAccount(issuer: "Issuer \($0)", name: "user\($0)", secret: Data("s\($0)".utf8))
        })
        let ids = harness.store.accounts.map(\.id)
        harness.store.deleteAll()

        #expect(harness.store.accounts.isEmpty)
        #expect(try harness.metadata.load().isEmpty)
        for id in ids {
            #expect(!harness.vault.hasSecret(for: id))
        }
    }

    @Test("Search filters on both issuer and account name")
    func searchFilters() {
        let harness = Harness()
        defer { harness.tearDown() }

        harness.store.importAccounts([
            ImportedAccount(issuer: "GitHub", name: "anhtd", secret: Data("a".utf8)),
            ImportedAccount(issuer: "Google", name: "alice@example.com", secret: Data("b".utf8)),
        ])

        harness.store.searchText = "git"
        #expect(harness.store.filteredAccounts.map(\.issuer) == ["GitHub"])

        harness.store.searchText = "example"
        #expect(harness.store.filteredAccounts.map(\.issuer) == ["Google"])

        harness.store.searchText = ""
        #expect(harness.store.filteredAccounts.count == 2)
    }

    @Test("Skipped entries are carried into the summary")
    func summaryCarriesSkipped() {
        let harness = Harness()
        defer { harness.tearDown() }

        let summary = harness.store.importAccounts(
            [ImportedAccount(issuer: "A", name: "a", secret: aliceSecret)],
            skipped: 2
        )
        #expect(summary.skipped == 2)
        #expect(summary.description == "1 added, 2 skipped")
    }

    /// A full round trip: the export QR the user scans has to end up as the
    /// code they see in the panel.
    @Test("An export QR becomes a visible code")
    func endToEndFromExportQR() throws {
        let harness = Harness()
        defer { harness.tearDown() }

        let payload = try MigrationDecoder.decode(MigrationRealVectorTests.aliceURL)
        harness.store.importAccounts(payload.accounts, skipped: payload.skippedCount)

        harness.setTime(Date(timeIntervalSince1970: 0))
        harness.store.refreshCodes(force: true)

        let account = try #require(harness.store.accounts.first)
        #expect(account.displayTitle == "Example")
        #expect(account.displaySubtitle == "alice@google.com")
        #expect(harness.store.codes[account.id] == "282760")
    }
}

/// macOS prompts for the login password once per Keychain item access control
/// list. One item per account therefore meant one prompt per account, and
/// "Always Allow" only authorised the single item it was shown for. These pin
/// the storage shape that fixes it.
@Suite("Single-item secret storage", .serialized)
@MainActor
struct SecretVaultStorageTests {
    private func secret(_ label: String) -> Data { Data("secret-\(label)".utf8) }

    /// The headline guarantee: prompts do not scale with account count.
    @Test("Many accounts still occupy exactly one Keychain item")
    func oneKeychainItemRegardlessOfAccountCount() {
        let harness = Harness()
        defer { harness.tearDown() }

        harness.store.importAccounts((0..<25).map {
            ImportedAccount(issuer: "Issuer \($0)", name: "user\($0)", secret: secret("\($0)"))
        })

        #expect(harness.store.accounts.count == 25)
        #expect(keychainItemCount(service: harness.service) == 1)
    }

    @Test("Adding more accounts later does not add more Keychain items")
    func repeatedImportsKeepOneItem() {
        let harness = Harness()
        defer { harness.tearDown() }

        for batch in 0..<4 {
            harness.store.importAccounts((0..<5).map {
                ImportedAccount(
                    issuer: "Batch \(batch)",
                    name: "user\(batch)-\($0)",
                    secret: secret("\(batch)-\($0)")
                )
            })
            #expect(keychainItemCount(service: harness.service) == 1)
        }
        #expect(harness.store.accounts.count == 20)
    }

    /// Secrets must survive a lock/unlock cycle through the encrypted file, not
    /// merely live in memory.
    @Test("Secrets round-trip through the encrypted file")
    func secretsSurviveALockCycle() throws {
        let harness = Harness()
        defer { harness.tearDown() }

        harness.store.importAccounts([
            ImportedAccount(issuer: "Example", name: "alice@google.com", secret: aliceSecret)
        ])
        let id = harness.store.accounts[0].id

        harness.vault.clearCache()
        #expect(harness.vault.cachedSecret(for: id) == nil)

        try harness.vault.open(knownAccountIDs: [id])
        #expect(harness.vault.cachedSecret(for: id) == aliceSecret)
    }

    /// The file on disk must be ciphertext — a plaintext secrets file would
    /// make the Keychain item pointless.
    @Test("The secrets file is encrypted at rest")
    func secretsFileIsCiphertext() throws {
        let harness = Harness()
        defer { harness.tearDown() }

        harness.store.importAccounts([
            ImportedAccount(issuer: "Example", name: "alice@google.com", secret: aliceSecret)
        ])

        let raw = try Data(contentsOf: harness.secretsFileURL)
        #expect(!raw.isEmpty)
        #expect(!raw.contains(aliceSecret))
        let text = String(decoding: raw, as: UTF8.self)
        #expect(!text.contains("Hello!"))
        #expect(!text.contains("alice@google.com"))
    }

    /// Existing installs already have one Keychain item per account. Those must
    /// be folded into the new store rather than lost.
    @Test("Secrets in the old per-account layout are migrated and cleaned up")
    func migratesLegacyPerAccountItems() throws {
        let harness = Harness()
        defer { harness.tearDown() }

        // Lay down the old shape: metadata plus one Keychain item per account.
        let legacy = KeychainStore(
            service: harness.service,
            usesDataProtectionKeychain: KeychainAvailability.shared.usesDataProtectionKeychain
        )
        let accounts = (0..<3).map {
            Account(issuer: "Issuer \($0)", name: "user\($0)", sortIndex: $0)
        }
        try harness.metadata.save(accounts)
        for (index, account) in accounts.enumerated() {
            try legacy.save(
                secret: secret("legacy-\(index)"),
                for: account.id.uuidString,
                protection: .none
            )
        }
        #expect(keychainItemCount(service: harness.service) == 3)

        try harness.vault.open(knownAccountIDs: accounts.map(\.id))

        // Every secret came across…
        for (index, account) in accounts.enumerated() {
            #expect(harness.vault.cachedSecret(for: account.id) == secret("legacy-\(index)"))
        }
        // …and the many old items collapsed into the single vault key.
        #expect(keychainItemCount(service: harness.service) == 1)
    }

    @Test("Removing everything leaves no Keychain item and no file")
    func deleteAllRemovesStorage() {
        let harness = Harness()
        defer { harness.tearDown() }

        harness.store.importAccounts((0..<5).map {
            ImportedAccount(issuer: "I\($0)", name: "u\($0)", secret: secret("\($0)"))
        })
        harness.store.deleteAll()

        #expect(keychainItemCount(service: harness.service) == 0)
        #expect(!FileManager.default.fileExists(atPath: harness.secretsFileURL.path))
        #expect(harness.store.accounts.isEmpty)
    }

    /// "Remove All" originally deleted only the new vault key, leaving items
    /// from the pre-vault layout behind. Because the metadata file is cleared at
    /// the same time, the app then had no record of their ids — so those items
    /// could never be found or removed again.
    @Test("Removing everything also clears items from the old per-account layout")
    func deleteAllRemovesLegacyItems() throws {
        let harness = Harness()
        defer { harness.tearDown() }

        let legacy = KeychainStore(
            service: harness.service,
            usesDataProtectionKeychain: KeychainAvailability.shared.usesDataProtectionKeychain
        )
        let accounts = (0..<6).map {
            Account(issuer: "Old \($0)", name: "user\($0)", sortIndex: $0)
        }
        try harness.metadata.save(accounts)
        for account in accounts {
            try legacy.save(
                secret: secret(account.name),
                for: account.id.uuidString,
                protection: .none
            )
        }
        harness.store.reload()
        #expect(keychainItemCount(service: harness.service) == 6)

        harness.store.deleteAll()

        #expect(keychainItemCount(service: harness.service) == 0)
        #expect(harness.store.accounts.isEmpty)
        #expect(try harness.metadata.load().isEmpty)
    }
}

@Suite("Account metadata file")
struct AccountMetadataStoreTests {
    private func makeStore() -> (AccountMetadataStore, URL) {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("MenuAuthMeta-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return (
            AccountMetadataStore(fileURL: directory.appendingPathComponent("accounts.json")),
            directory
        )
    }

    @Test("A missing file is an empty list, not an error")
    func missingFileIsEmpty() throws {
        let (store, directory) = makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        #expect(try store.load().isEmpty)
    }

    @Test("Accounts round-trip through the file")
    func roundTrip() throws {
        let (store, directory) = makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        let accounts = [
            Account(issuer: "GitHub", name: "anhtd", digits: 8, algorithm: .sha256,
                    period: 60, sortIndex: 0),
            Account(issuer: "Google", name: "me", sortIndex: 1),
        ]
        try store.save(accounts)

        let loaded = try store.load()
        #expect(loaded == accounts)
    }

    @Test("Accounts come back in sort order regardless of file order")
    func loadsInSortOrder() throws {
        let (store, directory) = makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        try store.save([
            Account(issuer: "C", name: "c", sortIndex: 2),
            Account(issuer: "A", name: "a", sortIndex: 0),
            Account(issuer: "B", name: "b", sortIndex: 1),
        ])
        #expect(try store.load().map(\.issuer) == ["A", "B", "C"])
    }

    @Test("The file is written owner-only")
    func fileIsOwnerReadableOnly() throws {
        let (store, directory) = makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        try store.save([Account(issuer: "A", name: "a")])
        let attributes = try FileManager.default.attributesOfItem(atPath: store.fileURL.path)
        let permissions = try #require(attributes[.posixPermissions] as? NSNumber)
        #expect(permissions.int16Value == 0o600)
    }
}
