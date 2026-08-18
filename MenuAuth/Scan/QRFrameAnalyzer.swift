import CoreVideo
import Foundation
import Vision

/// Finds QR codes in live camera frames.
///
/// The camera path originally used `AVCaptureMetadataOutput`, which is the
/// usual way to scan QR codes on iOS. On macOS it reported no support for the
/// QR type at all, so scanning failed with "this Mac's camera can't detect QR
/// codes". Vision has no such gap and is already used for still images, so both
/// paths now share one decoder.
///
/// Vision on every frame would be wasteful — a QR held up to a camera does not
/// change 60 times a second — so analysis is throttled. Everything here runs on
/// the capture queue and nowhere else, which is what makes the unsynchronised
/// `lastRun` safe.
nonisolated final class QRFrameAnalyzer: @unchecked Sendable {
    /// Four looks per second: fast enough that positioning a code feels
    /// instant, and roughly a fifteenth of the work of analysing every frame.
    static let defaultInterval: CFTimeInterval = 0.25

    private let request: VNDetectBarcodesRequest
    private let minimumInterval: CFTimeInterval
    private var lastRun: CFAbsoluteTime = 0

    init(minimumInterval: CFTimeInterval = defaultInterval) {
        self.minimumInterval = minimumInterval
        request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
    }

    /// Payloads visible in this frame, or an empty array when the frame was
    /// skipped by throttling or held no QR code.
    func payloads(in pixelBuffer: CVPixelBuffer, now: CFAbsoluteTime = CFAbsoluteTimeGetCurrent()) -> [String] {
        guard now - lastRun >= minimumInterval else { return [] }
        lastRun = now

        let handler = VNImageRequestHandler(cvPixelBuffer: pixelBuffer, options: [:])
        do {
            try handler.perform([request])
        } catch {
            return []
        }
        return (request.results ?? [])
            .compactMap(\.payloadStringValue)
            .filter { !$0.isEmpty }
    }

    /// Whether a frame at this instant would be analysed rather than skipped.
    func wouldAnalyze(at now: CFAbsoluteTime) -> Bool {
        now - lastRun >= minimumInterval
    }
}
