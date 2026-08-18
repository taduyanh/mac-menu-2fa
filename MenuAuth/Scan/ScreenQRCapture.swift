import CoreGraphics
import Foundation
import ScreenCaptureKit

/// Reads a QR code straight off the Mac's screen.
///
/// The point of this path is iPhone Mirroring: on macOS 26 you can run Google
/// Authenticator in a window on the Mac, open its export QR there, and import
/// without holding a phone up to a camera.
///
/// It captures on demand — one press, one grab — rather than watching the
/// screen continuously. Continuous capture would mean decoding a full-screen
/// image several times a second, which is exactly the kind of background cost
/// this app is built to avoid.
nonisolated enum ScreenQRCapture {
    enum Failure: Error, LocalizedError, Equatable {
        case permissionDenied
        case noDisplays
        case captureFailed(String)
        case noQRCodeFound

        var errorDescription: String? {
            switch self {
            case .permissionDenied:
                "MenuAuth needs Screen Recording permission to read a QR code from your "
                    + "screen. Enable it in System Settings ▸ Privacy & Security ▸ Screen "
                    + "Recording, then quit and reopen MenuAuth."
            case .noDisplays:
                "No display was available to capture."
            case .captureFailed(let detail):
                "Screen capture failed: \(detail)"
            case .noQRCodeFound:
                "No QR code was found on screen. Make sure the export QR is visible — "
                    + "in iPhone Mirroring, for example — and try again."
            }
        }
    }

    /// True when the Screen Recording permission has already been granted.
    /// Checked without prompting so the UI can explain itself first.
    static var hasPermission: Bool {
        CGPreflightScreenCaptureAccess()
    }

    /// Triggers the system permission prompt. macOS only shows it once per app;
    /// after a denial the user has to go to System Settings, which is what the
    /// `permissionDenied` message tells them.
    @discardableResult
    static func requestPermission() -> Bool {
        CGRequestScreenCaptureAccess()
    }

    /// Grabs every display and returns all QR payloads found on any of them.
    ///
    /// All payloads, not just the first: a multi-fragment export shown side by
    /// side, or a second monitor, should not need a second press.
    static func capturePayloads() async throws -> [String] {
        guard hasPermission else {
            requestPermission()
            throw Failure.permissionDenied
        }

        let content: SCShareableContent
        do {
            content = try await SCShareableContent.excludingDesktopWindows(
                false,
                onScreenWindowsOnly: true
            )
        } catch {
            // ScreenCaptureKit reports a missing permission as a generic
            // failure, so re-check rather than blaming the capture.
            throw hasPermission
                ? Failure.captureFailed(error.localizedDescription)
                : Failure.permissionDenied
        }

        guard !content.displays.isEmpty else { throw Failure.noDisplays }

        // Leaving MenuAuth's own panel in the shot would let it cover the very
        // QR the user is trying to capture.
        let ownApplication = content.applications.first {
            $0.bundleIdentifier == Bundle.main.bundleIdentifier
        }

        var payloads: [String] = []
        for display in content.displays {
            let filter = SCContentFilter(
                display: display,
                excludingApplications: ownApplication.map { [$0] } ?? [],
                exceptingWindows: []
            )

            let configuration = SCStreamConfiguration()
            let (width, height) = captureSize(for: display)
            configuration.width = width
            configuration.height = height
            configuration.showsCursor = false

            do {
                let image = try await SCScreenshotManager.captureImage(
                    contentFilter: filter,
                    configuration: configuration
                )
                payloads.append(contentsOf: try ImageQRDecoder.payloads(in: image))
            } catch let failure as ImageQRDecoder.Failure {
                throw Failure.captureFailed(failure.localizedDescription)
            } catch {
                throw Failure.captureFailed(error.localizedDescription)
            }
        }

        guard !payloads.isEmpty else { throw Failure.noQRCodeFound }
        return payloads
    }

    /// Captures above point resolution so a small QR — an iPhone Mirroring
    /// window is not large — keeps enough module detail to decode, while
    /// capping the pixel count so a 5K display does not produce a
    /// several-hundred-megabyte image.
    private static func captureSize(for display: SCDisplay) -> (width: Int, height: Int) {
        let maximumDimension = 3840.0
        let longestSide = Double(max(display.width, display.height))
        guard longestSide > 0 else { return (display.width, display.height) }

        let scale = min(2.0, max(1.0, maximumDimension / longestSide))
        return (Int(Double(display.width) * scale), Int(Double(display.height) * scale))
    }
}
