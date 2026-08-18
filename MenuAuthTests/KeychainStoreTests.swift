import Foundation
import Security
import Testing

@testable import MenuAuth

/// Counts the Keychain items a service owns, without triggering any prompt.
///
/// This is the measurement behind "one prompt instead of N": macOS asks for the
/// login password once per item access control list, so the item count *is* the
/// prompt count.
func keychainItemCount(service: String) -> Int {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecMatchLimit as String: kSecMatchLimitAll,
        kSecReturnAttributes as String: true,
        kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess, let items = result as? [[String: Any]] else { return 0 }
    return items.count
}

/// These run inside the sandboxed, ad-hoc-signed host app, so they report what
/// the Keychain actually does for *this* build — which is the question the plan
/// flagged as the main signing risk.
///
/// Every test uses `.none` protection: `.userPresence` items would block on a
/// Touch ID prompt and hang an automated run. The biometric path is verified
/// by hand (see README "Verifying the biometric gate").
@Suite("Keychain round-trip", .serialized)
struct KeychainStoreTests {
    /// A per-suite service name so these never collide with the real app's
    /// items, and so teardown can delete everything safely.
    private static let service = "com.anhtd.MenuAuth.tests"

    private func makeStore(dataProtection: Bool) -> KeychainStore {
        KeychainStore(service: Self.service, usesDataProtectionKeychain: dataProtection)
    }

    /// The data-protection keychain is the only place `SecAccessControl` is
    /// enforced, and reaching it requires an `application-identifier` or
    /// `keychain-access-groups` entitlement that only a team-signed build has.
    ///
    /// Rather than skip, this asserts whichever outcome is correct for how the
    /// app was signed — so the day a real signing identity is configured, the
    /// test starts exercising the stronger path automatically.
    @Test("Data-protection keychain works exactly when the entitlement is present")
    func dataProtectionRoundTrip() throws {
        let store = makeStore(dataProtection: true)
        let account = UUID().uuidString
        let secret = Data([0x01, 0x02, 0x03, 0xfe, 0xff, 0x00])

        guard KeychainAvailability.shared.usesDataProtectionKeychain else {
            #expect(throws: KeychainStore.Failure.unhandled(errSecMissingEntitlement)) {
                try store.save(secret: secret, for: account, protection: .none)
            }
            return
        }

        try? store.deleteAll()
        defer { try? store.deleteAll() }

        try store.save(secret: secret, for: account, protection: .none)
        #expect(store.containsSecret(for: account))
        #expect(try store.loadSecret(for: account) == secret)

        try store.delete(account: account)
        #expect(!store.containsSecret(for: account))
        #expect(throws: KeychainStore.Failure.notFound) {
            try store.loadSecret(for: account)
        }
    }

    /// Silently downgrading would be the dangerous outcome: the Keychain
    /// accepts an access-control attribute it cannot enforce, and the UI would
    /// then promise a Touch ID gate that does not exist.
    @Test("A gate that cannot be enforced is refused rather than faked")
    func refusesUnenforceableProtection() throws {
        let store = makeStore(dataProtection: false)
        defer { try? store.deleteAll() }

        #expect(throws: KeychainStore.Failure.protectionUnsupported) {
            try store.save(secret: Data("s".utf8), for: UUID().uuidString, protection: .userPresence)
        }
    }

    @Test("Legacy keychain: save, load, delete")
    func legacyRoundTrip() throws {
        let store = makeStore(dataProtection: false)
        try? store.deleteAll()
        defer { try? store.deleteAll() }

        let account = UUID().uuidString
        let secret = Data("a-secret".utf8)

        try store.save(secret: secret, for: account, protection: .none)
        #expect(store.containsSecret(for: account))
        #expect(try store.loadSecret(for: account) == secret)

        try store.delete(account: account)
        #expect(!store.containsSecret(for: account))
    }

    /// A secret with a NUL byte and high bytes must survive verbatim; the
    /// github.com export vector contains exactly that.
    @Test("Arbitrary secret bytes round-trip verbatim")
    func binarySecretRoundTrip() throws {
        let store = makeStore(dataProtection: KeychainAvailability.shared.usesDataProtectionKeychain)
        try? store.deleteAll()
        defer { try? store.deleteAll() }

        let account = UUID().uuidString
        let secret = Data([0x19, 0x00, 0x30, 0x90, 0x85, 0xef, 0x37, 0xad, 0x6f, 0x9d])

        try store.save(secret: secret, for: account, protection: .none)
        let loaded = try store.loadSecret(for: account)
        #expect(loaded == secret)
        #expect(loaded.count == 10)
    }

    @Test("Saving twice for the same account overwrites")
    func saveOverwrites() throws {
        let store = makeStore(dataProtection: KeychainAvailability.shared.usesDataProtectionKeychain)
        try? store.deleteAll()
        defer { try? store.deleteAll() }

        let account = UUID().uuidString
        try store.save(secret: Data("first".utf8), for: account, protection: .none)
        try store.save(secret: Data("second".utf8), for: account, protection: .none)

        #expect(try store.loadSecret(for: account) == Data("second".utf8))
        #expect(keychainItemCount(service: Self.service) == 1)
    }

    @Test("Deleting a missing item is not an error")
    func deleteMissingIsFine() throws {
        let store = makeStore(dataProtection: KeychainAvailability.shared.usesDataProtectionKeychain)
        try store.delete(account: UUID().uuidString)
    }

    /// On the legacy Keychain a single `SecItemDelete` removes only one match
    /// and still reports success, so this must loop.
    @Test("deleteAll removes every secret for the service")
    func deleteAllClearsService() throws {
        let store = makeStore(dataProtection: KeychainAvailability.shared.usesDataProtectionKeychain)
        try? store.deleteAll()
        defer { try? store.deleteAll() }

        let accounts = (0..<3).map { _ in UUID().uuidString }
        for account in accounts {
            try store.save(secret: Data(account.utf8), for: account, protection: .none)
        }
        try store.deleteAll()

        for account in accounts {
            #expect(!store.containsSecret(for: account))
        }
        #expect(keychainItemCount(service: Self.service) == 0)
    }

    /// Not an assertion so much as a recorded observation: this is the answer
    /// to "does the data-protection keychain work in an ad-hoc signed sandboxed
    /// build?", and it drives which mode the app picks at launch.
    @Test("Report which keychain mode this build can use")
    func reportAvailability() {
        let availability = KeychainAvailability.shared
        print(
            """

            ┌─ Keychain availability for this build ──────────────────
            │ data-protection keychain usable: \(availability.usesDataProtectionKeychain)
            │ \(availability.diagnostics)
            └─────────────────────────────────────────────────────────

            """
        )
        // Whichever mode was chosen must actually work end to end.
        #expect(availability.isUsable)
    }
}
