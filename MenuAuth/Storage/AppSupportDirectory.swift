import Foundation

nonisolated enum AppSupportDirectory {
    /// The app's private folder inside Application Support (its sandbox
    /// container, when sandboxed), created owner-only if missing.
    ///
    /// Non-throwing on purpose: the app must still launch and show its menu bar
    /// item if the folder cannot be prepared. A failure surfaces later as a
    /// load/save error in the panel instead of preventing startup.
    static func url(for identifier: String) -> URL {
        let support = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first ?? URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)

        let directory = support.appendingPathComponent(identifier, isDirectory: true)
        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return directory
    }
}
