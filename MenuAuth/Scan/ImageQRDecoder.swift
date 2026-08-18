import CoreGraphics
import Foundation
import Vision

/// Finds QR payloads in a still image — a screenshot, a photo AirDropped from
/// the phone, or something pasted from the clipboard.
///
/// This path needs no camera permission and no capture session, which is why
/// it exists alongside the live scanner: it is the cheapest way to import, and
/// the easiest to retry when a scan misreads.
nonisolated enum ImageQRDecoder {
    enum Failure: Error, LocalizedError {
        case unreadableImage
        case noQRCodeFound

        var errorDescription: String? {
            switch self {
            case .unreadableImage:
                "That file isn't an image MenuAuth can read."
            case .noQRCodeFound:
                "No QR code was found in that image. Try a sharper or larger screenshot."
            }
        }
    }

    /// Returns every QR payload in the image.
    ///
    /// All of them, not just the first: a photo of a phone screen can catch a
    /// neighbouring code, and a single screenshot may contain more than one
    /// fragment of a multi-part export.
    static func payloads(in imageData: Data) throws -> [String] {
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]

        let handler = VNImageRequestHandler(data: imageData, options: [:])
        do {
            try handler.perform([request])
        } catch {
            throw Failure.unreadableImage
        }

        let payloads = (request.results ?? [])
            .compactMap(\.payloadStringValue)
            .filter { !$0.isEmpty }

        guard !payloads.isEmpty else { throw Failure.noQRCodeFound }
        return payloads
    }

    /// Same, for an image already in memory — a screen capture, which never
    /// needs to be encoded to a file first.
    ///
    /// Unlike the `Data` variant, finding nothing returns an empty array rather
    /// than throwing: the caller sweeps several displays and only one of them is
    /// expected to hold the QR, so "empty" is the normal case per display.
    static func payloads(in image: CGImage) throws -> [String] {
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]

        let handler = VNImageRequestHandler(cgImage: image, options: [:])
        do {
            try handler.perform([request])
        } catch {
            throw Failure.unreadableImage
        }

        return (request.results ?? [])
            .compactMap(\.payloadStringValue)
            .filter { !$0.isEmpty }
    }

    static func payloads(at url: URL) throws -> [String] {
        // The import panel hands back a security-scoped URL when sandboxed.
        let needsScope = url.startAccessingSecurityScopedResource()
        defer { if needsScope { url.stopAccessingSecurityScopedResource() } }

        guard let data = try? Data(contentsOf: url) else {
            throw Failure.unreadableImage
        }
        return try payloads(in: data)
    }
}
