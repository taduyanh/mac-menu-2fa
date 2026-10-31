import AppKit
import CoreImage.CIFilterBuiltins

nonisolated enum QRCodeImage {
    private static let quietZoneModules: CGFloat = 4

    /// Renders `text` as a crisp black-on-white QR with a quiet zone, scaled by
    /// a whole number per module so edges stay sharp.
    static func make(from text: String, side: CGFloat = 264) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "L"
        guard let output = filter.outputImage else { return nil }

        let modules = output.extent.width
        let scale = max(((side / (modules + quietZoneModules * 2))).rounded(.down), 1)
        let scaled = output
            .samplingNearest()
            .transformed(by: CGAffineTransform(scaleX: scale, y: scale))

        let quiet = quietZoneModules * scale
        let canvas = scaled.extent.insetBy(dx: -quiet, dy: -quiet)
        let image = scaled.composited(
            over: CIImage(color: .white).cropped(to: canvas)
        )

        guard let cgImage = CIContext().createCGImage(image, from: canvas) else { return nil }
        return NSImage(cgImage: cgImage, size: NSSize(width: canvas.width, height: canvas.height))
    }
}
