import Foundation
import LocalAuthentication
import Security

/// Stores one TOTP secret per account as a generic password.
///
/// Only the secret lives here. Account metadata (issuer, label, digits) is kept
/// in `AccountMetadataStore`, so listing accounts and drawing the countdown
/// never touches the Keychain and never triggers an authentication prompt.
nonisolated struct KeychainStore: Sendable {
    /// How strongly an individual item is guarded.
    enum Protection: Sendable, Equatable {
        /// Reading requires Touch ID or the login password. The gate is
        /// enforced by the Keychain itself, not by app logic, so it holds even
        /// if the process is compromised.
        case userPresence
        /// No per-item gate. Used by tests, and by the "codes always visible"
        /// setting if it is ever offered.
        case none
    }

    enum Failure: Error, LocalizedError, Equatable {
        case notFound
        case authenticationCancelled
        case authenticationFailed
        case accessControlUnavailable(String)
        case protectionUnsupported
        case unhandled(OSStatus)

        var errorDescription: String? {
            switch self {
            case .notFound:
                "That account's secret is missing from the Keychain."
            case .authenticationCancelled:
                "Authentication was cancelled."
            case .authenticationFailed:
                "Authentication failed."
            case .accessControlUnavailable(let detail):
                "Couldn't set up Keychain protection: \(detail)"
            case .protectionUnsupported:
                "This build can't apply a Keychain-enforced Touch ID gate. "
                    + "Sign the app with an Apple Developer team to enable it."
            case .unhandled(let status):
                "Keychain error \(status): "
                    + (SecCopyErrorMessageString(status, nil) as String? ?? "unknown")
            }
        }
    }

    let service: String

    /// macOS offers two Keychain implementations. The data-protection keychain
    /// is the modern, iOS-style one and is required for `SecAccessControl` to
    /// mean anything — but it demands that the app carry an
    /// `application-identifier` or `keychain-access-groups` entitlement, which
    /// an ad-hoc signed build does not have. `KeychainAvailability` probes at
    /// launch and picks the mode that actually works on this machine.
    let usesDataProtectionKeychain: Bool

    init(service: String, usesDataProtectionKeychain: Bool) {
        self.service = service
        self.usesDataProtectionKeychain = usesDataProtectionKeychain
    }

    // MARK: - Writing

    func save(secret: Data, for account: String, protection: Protection) throws {
        // Delete first: SecItemUpdate cannot change an item's access control,
        // and a re-import must be able to change protection level.
        try? delete(account: account)

        var query = baseQuery(for: account)
        query[kSecValueData as String] = secret

        switch protection {
        case .userPresence:
            // `SecAccessControl` is only *enforced* on the data-protection
            // keychain. The legacy keychain accepts the attribute and ignores
            // it, which is worse than refusing: the UI would promise a gate
            // that does not exist. Fail loudly and let the caller downgrade
            // deliberately.
            guard usesDataProtectionKeychain else { throw Failure.protectionUnsupported }
            query[kSecAttrAccessControl as String] = try makeAccessControl()
        case .none:
            query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw mapError(status) }
    }

    // MARK: - Reading

    /// Reads a secret, prompting for biometrics if the item requires it.
    ///
    /// Pass an already-authenticated `LAContext` to reuse a single prompt
    /// across a burst of reads — otherwise the user is asked once per account.
    func loadSecret(for account: String, context: LAContext? = nil) throws -> Data {
        var query = baseQuery(for: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { throw mapError(status) }
        guard let data = result as? Data else { throw Failure.notFound }
        return data
    }

    /// Existence check that never prompts.
    ///
    /// Asking for attributes instead of data means the Keychain does not need
    /// to decrypt the item, so a `.userPresence` gate is not triggered.
    func containsSecret(for account: String) -> Bool {
        var query = baseQuery(for: account)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        // `interactionNotAllowed` means the item exists but would need a prompt.
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    // MARK: - Deleting

    func delete(account: String) throws {
        let status = SecItemDelete(baseQuery(for: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw mapError(status)
        }
    }

    /// Removes every secret this app owns. Used by "Remove all accounts" and by
    /// test teardown.
    ///
    /// The loop is not defensive padding: on the legacy macOS Keychain a single
    /// `SecItemDelete` with a multi-match query removes only *one* item and
    /// still reports success, so a one-shot call silently leaves secrets behind.
    func deleteAll() throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        if usesDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain as String] = true
        }

        // Bounded so a Keychain that kept reporting success could never spin.
        for _ in 0..<Self.maximumAccounts {
            let status = SecItemDelete(query as CFDictionary)
            switch status {
            case errSecSuccess: continue
            case errSecItemNotFound: return
            default: throw mapError(status)
            }
        }
        throw Failure.unhandled(errSecInternalError)
    }

    /// An upper bound on how many accounts one install can hold. Google's own
    /// exports top out far below this; it exists only to bound the delete loop.
    static let maximumAccounts = 1000

    // MARK: - Internals

    private func baseQuery(for account: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if usesDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain as String] = true
            // Only meaningful on the data-protection keychain; the legacy one
            // has no notion of a non-syncable-by-attribute item.
            query[kSecAttrSynchronizable as String] = false
        }
        return query
    }

    private func makeAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        let control = SecAccessControlCreateWithFlags(
            nil,
            // Never leaves this Mac, and unavailable while the screen is locked.
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            &error
        )
        guard let control else {
            let detail = (error?.takeRetainedValue() as (any Error)?)?.localizedDescription
                ?? "unknown"
            throw Failure.accessControlUnavailable(detail)
        }
        return control
    }

    private func mapError(_ status: OSStatus) -> Failure {
        switch status {
        case errSecItemNotFound: .notFound
        case errSecUserCanceled: .authenticationCancelled
        case errSecAuthFailed: .authenticationFailed
        default: .unhandled(status)
        }
    }
}
