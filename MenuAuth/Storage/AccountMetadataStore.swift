import Foundation

/// Persists the non-secret half of each account as JSON.
///
/// Keeping metadata out of the Keychain is what lets the panel draw the account
/// list and countdown rings without authenticating. Nothing here is sensitive
/// on its own: an attacker learns *which* services you use, which they could
/// also learn from your browser history, but never a secret.
nonisolated struct AccountMetadataStore: Sendable {
    enum Failure: Error, LocalizedError {
        case directoryUnavailable(String)

        var errorDescription: String? {
            switch self {
            case .directoryUnavailable(let detail):
                "Couldn't open MenuAuth's data folder: \(detail)"
            }
        }
    }

    let fileURL: URL

    init(fileURL: URL) {
        self.fileURL = fileURL
    }

    /// The default location inside the app's Application Support directory
    /// (its sandbox container, when sandboxed).
    ///
    /// Non-throwing on purpose: the app must still launch and show its menu bar
    /// item if the directory cannot be prepared. A failure here surfaces as a
    /// load/save error in the panel instead of preventing startup.
    static func makeDefault(
        bundleIdentifier: String = Bundle.main.bundleIdentifier ?? "com.anhtd.MenuAuth"
    ) -> AccountMetadataStore {
        let support = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first ?? URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)

        let directory = support.appendingPathComponent(bundleIdentifier, isDirectory: true)
        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return AccountMetadataStore(
            fileURL: directory.appendingPathComponent("accounts.json", isDirectory: false)
        )
    }

    /// Returns an empty list when the file does not exist yet — a first launch
    /// is not an error.
    func load() throws -> [Account] {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return [] }
        let data = try Data(contentsOf: fileURL)
        guard !data.isEmpty else { return [] }
        let accounts = try JSONDecoder().decode([Account].self, from: data)
        return accounts.sorted { $0.sortIndex < $1.sortIndex }
    }

    func save(_ accounts: [Account]) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(accounts)

        // Atomic so a crash mid-write cannot leave a truncated list that would
        // orphan Keychain items.
        try data.write(to: fileURL, options: [.atomic])
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: fileURL.path
        )
    }

    func deleteFile() throws {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return }
        try FileManager.default.removeItem(at: fileURL)
    }
}
