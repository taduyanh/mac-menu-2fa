import CryptoKit
import Foundation
import LocalAuthentication
import Observation

/// The only component that ever holds a plaintext TOTP secret.
///
/// Every secret lives in one AES-GCM encrypted file, and the Keychain holds a
/// single item: the key to that file. This shape exists because the Keychain
/// prompts for the login password once per *item* access control list — one
/// item per account meant one prompt per account, and "Always Allow" only ever
/// applied to the one item it was shown for. One item means one prompt.
@Observable
final class SecretVault {
    /// The Keychain account name of the single item this app owns.
    static let vaultKeyName = "vault-key"

    private let keychain: KeychainStore
    private let file: EncryptedSecretsFile
    private let availability: KeychainAvailability

    private var cache: [UUID: Data] = [:]
    /// Held only while unlocked; dropped with the secrets on re-lock.
    private var key: SymmetricKey?
    private(set) var isOpen = false

    /// The protection this build was actually able to apply — not what it
    /// would like to have applied.
    let enforcement: BiometricGate.Enforcement

    init(
        service: String = Bundle.main.bundleIdentifier ?? "com.anhtd.MenuAuth",
        secretsFileURL: URL? = nil,
        availability: KeychainAvailability = .shared
    ) {
        self.availability = availability
        keychain = KeychainStore(
            service: service,
            usesDataProtectionKeychain: availability.usesDataProtectionKeychain
        )
        file = EncryptedSecretsFile(
            fileURL: secretsFileURL ?? AppSupportDirectory.url(for: service)
                .appendingPathComponent("secrets.dat", isDirectory: false)
        )
        enforcement = if availability.supportsUserPresence {
            .keychainEnforced
        } else if availability.canAuthenticateUser {
            .appEnforced
        } else {
            .unavailable
        }
    }

    private var writeProtection: KeychainStore.Protection {
        availability.supportsUserPresence ? .userPresence : .none
    }

    // MARK: - Opening

    /// Fetches the vault key and decrypts every secret.
    ///
    /// This is the single point where the Keychain is touched, so it is also
    /// the only place the user can be prompted — once, for one item, whatever
    /// the account count.
    func open(context: LAContext? = nil, knownAccountIDs: [UUID] = []) throws {
        guard !isOpen else { return }

        let key = try loadOrCreateKey(context: context)
        self.key = key

        var secrets = try file.load(key: key)
        // First run after the storage change: fold in anything still sitting in
        // the old one-item-per-account layout so no account is lost.
        if let migrated = try migrateLegacyItems(knownAccountIDs: knownAccountIDs, into: secrets) {
            secrets = migrated
            try file.save(secrets, key: key)
            discardLegacyItems(knownAccountIDs)
        }

        cache = secrets
        isOpen = true
    }

    private func loadOrCreateKey(context: LAContext?) throws -> SymmetricKey {
        do {
            let raw = try keychain.loadSecret(for: Self.vaultKeyName, context: context)
            return SymmetricKey(data: raw)
        } catch KeychainStore.Failure.notFound {
            let key = SymmetricKey(size: .bits256)
            let raw = key.withUnsafeBytes { Data($0) }
            try keychain.save(secret: raw, for: Self.vaultKeyName, protection: writeProtection)
            return key
        }
    }

    // MARK: - Legacy migration

    /// Reads secrets still stored as one Keychain item per account.
    ///
    /// Returns `nil` when there is nothing to migrate, so the common path does
    /// no extra work. This is the one moment the old per-account prompts can
    /// still appear — once, and never again afterwards.
    private func migrateLegacyItems(
        knownAccountIDs: [UUID],
        into existing: [UUID: Data]
    ) throws -> [UUID: Data]? {
        let missing = knownAccountIDs.filter { existing[$0] == nil }
        guard !missing.isEmpty else { return nil }

        var merged = existing
        var recovered = 0
        for id in missing {
            guard let secret = try? keychain.loadSecret(for: id.uuidString) else { continue }
            merged[id] = secret
            recovered += 1
        }
        return recovered > 0 ? merged : nil
    }

    private func discardLegacyItems(_ ids: [UUID]) {
        for id in ids {
            try? keychain.delete(account: id.uuidString)
        }
    }

    // MARK: - Writing

    /// Stores several secrets in one pass, so an import writes the file once
    /// rather than once per account.
    ///
    /// The file is written first and the cache updated only once that
    /// succeeds, so a failed write can't leave secrets in memory that the next
    /// successful save would then persist.
    func store(_ secrets: [UUID: Data], context: LAContext? = nil) throws {
        let key = try ensureKey(context: context)
        let updated = cache.merging(secrets) { _, new in new }
        try file.save(updated, key: key)
        cache = updated
        isOpen = true
    }

    func delete(id: UUID) throws {
        let key = try ensureKey(context: nil)
        var updated = cache
        updated.removeValue(forKey: id)
        try file.save(updated, key: key)
        cache = updated
        try? keychain.delete(account: id.uuidString) // in case a legacy item lingers
    }

    func deleteAll() throws {
        try file.delete()
        // Deletes every item this app owns, not just the vault key: installs
        // that predate the single-item store still have one item per account.
        // Removing only the key would orphan those forever — once the metadata
        // file is cleared the app no longer knows their ids, so nothing could
        // ever find them again.
        try keychain.deleteAll()
        clearCache()
    }

    private func ensureKey(context: LAContext?) throws -> SymmetricKey {
        if let key { return key }
        let key = try loadOrCreateKey(context: context)
        // Anything already on disk must be preserved rather than overwritten by
        // a cache that was never populated. A failure here is deliberately not
        // swallowed: if the file can't be decrypted, pressing on would seal an
        // empty store over it and destroy every secret it still holds.
        if cache.isEmpty {
            cache = try file.load(key: key)
        }
        self.key = key
        return key
    }

    // MARK: - Reading

    func hasSecret(for id: UUID) -> Bool {
        cache[id] != nil
    }

    /// The cached secret, or `nil` when still locked. Never prompts, so it is
    /// safe to call from a view body.
    func cachedSecret(for id: UUID) -> Data? {
        cache[id]
    }

    /// Ids the store has no secret for, which the UI flags per row.
    func missingSecretIDs(from ids: [UUID]) -> [UUID] {
        ids.filter { cache[$0] == nil }
    }

    /// Drops all plaintext, and the key with it. Called when the gate re-locks.
    func clearCache() {
        // Each secret is removed from the dictionary *before* being overwritten,
        // for two reasons. Taking ownership first means the buffer is uniquely
        // referenced, so the zeroing lands on the real allocation instead of a
        // copy-on-write duplicate. It also avoids reading `cache` (to iterate)
        // while writing to it, which is overlapping exclusive access to the
        // same property and traps at runtime.
        for identifier in Array(cache.keys) {
            guard var secret = cache.removeValue(forKey: identifier) else { continue }
            secret.withUnsafeMutableBytes { buffer in
                guard let base = buffer.baseAddress, buffer.count > 0 else { return }
                // `memset_s` is specified not to be optimised away, unlike a
                // plain loop or `memset` over memory that is about to be freed.
                _ = memset_s(base, buffer.count, 0, buffer.count)
            }
        }
        cache.removeAll()
        key = nil
        isOpen = false
    }
}
