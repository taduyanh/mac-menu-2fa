import AppKit

nonisolated enum Pasteboard {
    /// Clipboard managers watch for this type and are expected to skip the
    /// entry. A one-time code sitting in clipboard history would outlive its
    /// own 30-second validity by weeks.
    private static let concealedType = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")

    /// How long a copied code stays on the clipboard. Matches the TOTP window,
    /// after which the code is worthless anyway.
    static let clearDelay: Duration = .seconds(30)

    @MainActor private static var clearTask: Task<Void, Never>?

    @MainActor
    static func copyCode(_ code: String, clearAfter delay: Duration = clearDelay) {
        let pasteboard = NSPasteboard.general
        // `.currentHostOnly` keeps the code off Universal Clipboard, so it is
        // never relayed to the user's other devices.
        pasteboard.prepareForNewContents(with: .currentHostOnly)
        pasteboard.setString(code, forType: .string)
        pasteboard.setString("", forType: concealedType)

        scheduleClear(of: pasteboard.changeCount, after: delay)
    }

    /// Wipes the clipboard once the code has expired — but only if it still
    /// holds *our* copy. If the user has copied something else since, that
    /// is theirs to keep.
    @MainActor
    private static func scheduleClear(of changeCount: Int, after delay: Duration) {
        clearTask?.cancel()
        clearTask = Task {
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled else { return }
            let pasteboard = NSPasteboard.general
            if pasteboard.changeCount == changeCount {
                pasteboard.clearContents()
            }
        }
    }
}
