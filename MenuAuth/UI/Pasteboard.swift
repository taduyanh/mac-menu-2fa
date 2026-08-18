import AppKit

nonisolated enum Pasteboard {
    /// Clipboard managers watch for this type and are expected to skip the
    /// entry. A one-time code sitting in clipboard history would outlive its
    /// own 30-second validity by weeks.
    private static let concealedType = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")

    @MainActor
    static func copyCode(_ code: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(code, forType: .string)
        pasteboard.setString("", forType: concealedType)
    }
}
