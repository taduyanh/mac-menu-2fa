import CryptoKit
import Foundation
import Testing

@testable import MenuAuth

/// Regression tests for hostile or damaged input. Each one pins down a way the
/// app used to crash, or to lose or replace a secret, when fed bad data.
@Suite("Hostile input")
struct HostileInputTests {
    private let entry: (secret: Data, name: String, issuer: String, algorithm: UInt64?, digits: UInt64?, type: UInt64?)
        = (Data("secret".utf8), "alice", "Example", 1, 1, 2)

    /// `Int(UInt64)` traps on overflow, so a varint of 2^63 or more in a batch
    /// field used to take the whole app down from a single scanned QR.
    @Test(
        "An out-of-range batch field is rejected, not a crash",
        arguments: [UInt64(1) << 63, UInt64.max, UInt64(Int.max) + 1, 1_000_000]
    )
    func hugeBatchFieldsAreRejected(value: UInt64) {
        for field in 3...5 {
            var writer = ProtoWriter()
            writer.message(field: 1) { parameters in
                parameters.bytes(field: 1, entry.secret)
                parameters.string(field: 2, entry.name)
            }
            writer.varint(field: field, value)

            // Field 5 (the batch id) is only compared for equality, so a
            // 63-bit value is legitimate there; everything else must throw.
            if field == 5, value <= UInt64(Int.max) { continue }
            #expect(throws: ImportError.self) {
                try MigrationDecoder.decode(protobuf: writer.data)
            }
        }
    }

    @Test("A fragment index outside its own batch is rejected")
    func indexOutsideBatchIsRejected() {
        let payload = ProtoWriter.migrationPayload(
            entries: [entry], batchSize: 2, batchIndex: 5, batchID: 1
        )
        #expect(throws: ImportError.self) {
            try MigrationDecoder.decode(protobuf: payload)
        }
    }

    @Test("An oversized input string is refused before it is decoded")
    func oversizedInputIsRefused() {
        let padding = String(repeating: "A", count: MigrationDecoder.maximumInputLength + 1)
        #expect(throws: ImportError.self) {
            try MigrationDecoder.decode("otpauth-migration://offline?data=" + padding)
        }
        #expect(throws: ImportError.self) {
            try OTPAuthURL.decode("otpauth://totp/a:b?secret=" + padding)
        }
    }

    @Test("An implausibly long secret is skipped rather than stored")
    func oversizedSecretIsSkipped() throws {
        let payload = ProtoWriter.migrationPayload(entries: [
            (Data(repeating: 1, count: MigrationDecoder.maximumSecretLength + 1), "a", "b", 1, 1, 2),
            entry,
        ])
        let decoded = try MigrationDecoder.decode(protobuf: payload)
        #expect(decoded.accounts.count == 1)
        #expect(decoded.skippedCount == 1)
    }

    @Test("A payload with more entries than the app can hold is rejected")
    func tooManyEntriesIsRejected() {
        let payload = ProtoWriter.migrationPayload(
            entries: Array(repeating: entry, count: MigrationDecoder.maximumAccountsPerPayload + 1)
        )
        #expect(throws: ImportError.self) {
            try MigrationDecoder.decode(protobuf: payload)
        }
    }
}

@Suite("Damaged account metadata")
struct DamagedMetadataTests {
    /// `period: 0` reaches a `precondition` in `TOTP`, which would crash the app
    /// each time the panel opened for as long as the file stayed that way.
    @Test("Out-of-range digits and period are clamped when loading")
    func clampsDigitsAndPeriod() throws {
        let json = """
        [{"id":"\(UUID().uuidString)","issuer":"A","name":"b","digits":99,
          "algorithm":"sha1","period":0,"sortIndex":0},
         {"id":"\(UUID().uuidString)","issuer":"C","name":"d","digits":-3,
          "algorithm":"sha1","period":999999,"sortIndex":1}]
        """
        let accounts = try JSONDecoder().decode([Account].self, from: Data(json.utf8))

        for account in accounts {
            #expect(account.period == TOTP.defaultPeriod)
            #expect(account.digits == TOTP.defaultDigits)
        }
    }

    @Test("In-range values are preserved")
    func keepsValidValues() throws {
        let original = Account(issuer: "A", name: "b", digits: 8, algorithm: .sha256, period: 60)
        let decoded = try JSONDecoder().decode(
            Account.self, from: JSONEncoder().encode(original)
        )
        #expect(decoded == original)
    }
}

@Suite("Settings hygiene")
struct SettingsHygieneTests {
    @Test("A tampered idle timeout falls back to the default", arguments: [-1.0, 7.0, 1e12])
    func rejectsUnofferedTimeout(value: Double) throws {
        let name = "MenuAuthTests-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        defaults.set(value, forKey: AppSettings.Key.idleTimeout)

        #expect(AppSettings(defaults: defaults).idleTimeout == 300)
    }
}

@Suite("Secret vault integrity", .serialized)
struct VaultIntegrityTests {
    /// If the file can't be decrypted, writing must fail rather than seal an
    /// empty store over it — that would destroy every secret still inside.
    @Test("A store that can't be decrypted is not overwritten by a write")
    func undecryptableFileIsNotClobbered() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("MenuAuthTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let fileURL = directory.appendingPathComponent("secrets.dat")
        let sealedUnderAnotherKey = try #require(
            AES.GCM.seal(Data("{}".utf8), using: SymmetricKey(size: .bits256)).combined
        )
        try sealedUnderAnotherKey.write(to: fileURL)

        let service = "com.anhtd.MenuAuth.tests.integrity-\(UUID().uuidString)"
        let vault = SecretVault(service: service, secretsFileURL: fileURL)
        defer {
            try? vault.deleteAll()
            try? FileManager.default.removeItem(at: directory)
        }

        #expect(throws: EncryptedSecretsFile.Failure.self) {
            try vault.store([UUID(): Data("new".utf8)])
        }
        #expect(try Data(contentsOf: fileURL) == sealedUnderAnotherKey)
    }
}

@Suite("Import overwrite detection", .serialized)
@MainActor
struct OverwriteDetectionTests {
    @Test("Only entries matching an existing account count as overwrites")
    func countsCollisions() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("MenuAuthTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let service = "com.anhtd.MenuAuth.tests.overwrite-\(UUID().uuidString)"
        let vault = SecretVault(
            service: service,
            secretsFileURL: directory.appendingPathComponent("secrets.dat")
        )
        let store = AccountStore(
            metadata: AccountMetadataStore(fileURL: directory.appendingPathComponent("accounts.json")),
            vault: vault,
            gate: BiometricGate(enforcement: .unavailable)
        )
        defer {
            try? vault.deleteAll()
            try? FileManager.default.removeItem(at: directory)
        }

        store.importAccounts([
            ImportedAccount(issuer: "Google", name: "me@example.com", secret: Data("real".utf8))
        ])

        let incoming = [
            // Same account, different case — still a collision.
            ImportedAccount(issuer: "GOOGLE", name: "ME@example.com", secret: Data("evil".utf8)),
            ImportedAccount(issuer: "GitHub", name: "me", secret: Data("new".utf8)),
        ]
        #expect(store.overwriteCount(for: incoming) == 1)
        #expect(store.overwriteCount(for: [incoming[1]]) == 0)
    }
}
