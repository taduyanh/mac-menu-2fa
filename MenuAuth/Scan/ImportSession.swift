import Foundation
import Observation

/// Import state that outlives the panel.
///
/// This exists because of how the screen-capture flow actually plays out: to
/// swipe to the next QR of a multi-fragment export, the user has to click the
/// iPhone Mirroring window — which dismisses the menu bar panel and tears down
/// the import view. If the collector lived in `@State` there, "Scanned 1 of 3"
/// would be forgotten every time they went to fetch fragment 2, and the import
/// could never complete.
@Observable
final class ImportSession {
    /// Where QR codes are being read from.
    enum Source: String, CaseIterable, Identifiable {
        case camera
        case screen
        case image

        var id: String { rawValue }

        var title: String {
            switch self {
            case .camera: "Camera"
            case .screen: "Screen"
            case .image: "Image"
            }
        }

        var symbol: String {
            switch self {
            case .camera: "camera"
            case .screen: "macwindow"
            case .image: "photo"
            }
        }
    }

    private(set) var collector = BatchCollector()
    var source: Source = .camera
    var statusMessage: String?
    var errorMessage: String?
    var isCapturing = false

    /// Something has been scanned but not yet committed, so reopening the panel
    /// should drop the user back into the import view.
    var isInProgress: Bool { !collector.isEmpty }

    var accounts: [ImportedAccount] { collector.accounts }
    var skippedCount: Int { collector.skippedCount }
    var isComplete: Bool { collector.isComplete }
    var progressDescription: String { collector.progressDescription }
    var nextMissingFragment: Int? { collector.nextMissingFragment }

    /// Decodes a raw QR string and folds it in. Returns whether the caller
    /// should now commit (a complete export).
    @discardableResult
    func accept(_ text: String) -> Bool {
        do {
            let payload = try QRPayload.decode(text)
            switch collector.accept(payload) {
            case .accepted(let newAccounts):
                errorMessage = nil
                if newAccounts > 0 {
                    statusMessage = "Found \(newAccounts) account\(newAccounts == 1 ? "" : "s")."
                }
                return collector.isComplete
            case .alreadyScanned:
                // The camera is simply still pointed at the same code, or the
                // user pressed Capture twice. Not worth saying anything.
                return false
            case .differentExport:
                errorMessage = ImportError.mismatchedBatch.localizedDescription
                return false
            }
        } catch {
            // Payloads only arrive for QR codes that actually decoded, so an
            // error here means a real but unrelated code — worth naming. Once a
            // batch is under way we stay quiet, so a stray code in frame cannot
            // bury the "scan the next fragment" prompt.
            if collector.isEmpty || !(error is ImportError) {
                errorMessage = error.localizedDescription
            }
            return false
        }
    }

    func reset() {
        collector.reset()
        statusMessage = nil
        errorMessage = nil
        isCapturing = false
    }
}
