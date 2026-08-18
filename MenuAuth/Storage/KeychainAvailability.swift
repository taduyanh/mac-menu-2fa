import Foundation
import LocalAuthentication
import Security

/// Decides, once per launch, how this particular build can talk to the Keychain.
///
/// The answer is not knowable at compile time. macOS has two Keychain
/// implementations, and the modern data-protection one — the only one where
/// `SecAccessControl` and `.userPresence` actually mean anything — requires the
/// app to carry an `application-identifier` or `keychain-access-groups`
/// entitlement. A build signed with a real team has one; an ad-hoc "sign to run
/// locally" build does not.
///
/// Rather than guess, this writes a throwaway item and reads it back. The app
/// then uses whichever mode succeeded, and reports honestly in Settings which
/// protection it was able to apply.
nonisolated final class KeychainAvailability: Sendable {
    static let shared = KeychainAvailability(service: "com.anhtd.MenuAuth.probe")

    let usesDataProtectionKeychain: Bool
    /// True when the Keychain can store items at all, in either mode.
    let isUsable: Bool
    /// True when items can additionally be gated on Touch ID by the Keychain
    /// itself. Requires the data-protection keychain *and* an enrolled
    /// biometric or a settable password.
    let supportsUserPresence: Bool
    /// True when this Mac can authenticate the user at all — Touch ID or the
    /// login password. Independent of which Keychain is in use, so it is what
    /// an app-level gate can rely on.
    let canAuthenticateUser: Bool
    let diagnostics: String

    init(service: String) {
        var notes: [String] = []

        let dataProtectionWorks = Self.probeRoundTrip(
            service: service,
            usesDataProtectionKeychain: true,
            notes: &notes
        )
        var legacyWorks = false
        if !dataProtectionWorks {
            legacyWorks = Self.probeRoundTrip(
                service: service,
                usesDataProtectionKeychain: false,
                notes: &notes
            )
        }

        usesDataProtectionKeychain = dataProtectionWorks
        isUsable = dataProtectionWorks || legacyWorks

        // `.userPresence` is only enforceable on the data-protection keychain.
        // On the legacy keychain the flag is accepted and then ignored, which
        // would be worse than not offering it: the UI would claim a protection
        // that is not there.
        var context = LAContext()
        var authError: NSError?
        let canAuthenticate = context.canEvaluatePolicy(
            .deviceOwnerAuthentication,
            error: &authError
        )
        supportsUserPresence = dataProtectionWorks && canAuthenticate
        canAuthenticateUser = canAuthenticate

        if !canAuthenticate {
            notes.append("local authentication unavailable: \(authError?.localizedDescription ?? "unknown")")
        }
        if dataProtectionWorks {
            notes.append("using the data-protection keychain")
        } else if legacyWorks {
            notes.append("falling back to the legacy keychain (no per-item biometric gate)")
        } else {
            notes.append("KEYCHAIN UNUSABLE — secrets cannot be stored")
        }
        diagnostics = notes.joined(separator: "; ")

        // Nothing else should hold the probe context.
        context = LAContext()
        _ = context
    }

    /// Writes and reads back a throwaway item. Uses no access control so the
    /// probe never prompts the user at launch.
    private static func probeRoundTrip(
        service: String,
        usesDataProtectionKeychain: Bool,
        notes: inout [String]
    ) -> Bool {
        let label = usesDataProtectionKeychain ? "data-protection" : "legacy"
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "probe",
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        if usesDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain as String] = true
        }

        SecItemDelete(query as CFDictionary)

        var addQuery = query
        addQuery[kSecValueData as String] = Data([0x01])
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            notes.append("\(label) add failed (\(describe(addStatus)))")
            return false
        }

        defer { SecItemDelete(query as CFDictionary) }

        var readQuery = query
        readQuery[kSecReturnData as String] = true
        readQuery[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let readStatus = SecItemCopyMatching(readQuery as CFDictionary, &result)
        guard readStatus == errSecSuccess, (result as? Data) == Data([0x01]) else {
            notes.append("\(label) read failed (\(describe(readStatus)))")
            return false
        }
        return true
    }

    private static func describe(_ status: OSStatus) -> String {
        let message = SecCopyErrorMessageString(status, nil) as String? ?? "unknown"
        return "OSStatus \(status): \(message)"
    }
}
