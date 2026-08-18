import CoreGraphics
import CoreImage
import CoreVideo
import Foundation
import Testing

@testable import MenuAuth

/// Renders a QR code into a `CVPixelBuffer` shaped like a camera frame.
///
/// This is what lets the live-camera decode path be tested with no camera and
/// no hardware — the analyzer cannot tell this from a real frame.
private func makeQRPixelBuffer(
    payload: String,
    scale: CGFloat = 8,
    quietZone: CGFloat = 24
) throws -> CVPixelBuffer {
    let filter = try #require(CIFilter(name: "CIQRCodeGenerator"))
    filter.setValue(Data(payload.utf8), forKey: "inputMessage")
    filter.setValue("M", forKey: "inputCorrectionLevel")

    let generated = try #require(filter.outputImage)
        .transformed(by: CGAffineTransform(scaleX: scale, y: scale))

    // QR generators emit black on transparent; Vision needs it on white, and a
    // real scan always has a quiet zone around the code.
    let framed = generated.extent.insetBy(dx: -quietZone, dy: -quietZone)
    let composited = generated
        .composited(over: CIImage(color: .white).cropped(to: framed))
        .transformed(by: CGAffineTransform(translationX: -framed.minX, y: -framed.minY))

    let width = Int(framed.width)
    let height = Int(framed.height)
    var buffer: CVPixelBuffer?
    let status = CVPixelBufferCreate(
        kCFAllocatorDefault,
        width,
        height,
        kCVPixelFormatType_32BGRA,
        [
            kCVPixelBufferCGImageCompatibilityKey: true,
            kCVPixelBufferCGBitmapContextCompatibilityKey: true,
        ] as CFDictionary,
        &buffer
    )
    #expect(status == kCVReturnSuccess)

    let pixelBuffer = try #require(buffer)
    CIContext().render(composited, to: pixelBuffer)
    return pixelBuffer
}

private func makeBlankPixelBuffer(width: Int = 320, height: Int = 240) throws -> CVPixelBuffer {
    var buffer: CVPixelBuffer?
    CVPixelBufferCreate(
        kCFAllocatorDefault,
        width,
        height,
        kCVPixelFormatType_32BGRA,
        nil,
        &buffer
    )
    return try #require(buffer)
}

/// The camera scanner originally used `AVCaptureMetadataOutput`, which reported
/// no QR support on macOS and left the scanner showing "this Mac's camera can't
/// detect QR codes". These cover the Vision-based replacement.
@Suite("Live camera frame decoding")
struct QRFrameAnalyzerTests {
    @Test("A real export QR is decoded out of a camera frame")
    func decodesExportQRFromFrame() throws {
        let analyzer = QRFrameAnalyzer()
        let frame = try makeQRPixelBuffer(payload: MigrationRealVectorTests.aliceURL)

        let payloads = analyzer.payloads(in: frame, now: 1000)
        #expect(payloads == [MigrationRealVectorTests.aliceURL])
    }

    /// The decoded frame must survive the full pipeline, not merely be a string.
    @Test("A decoded frame imports as a real account")
    func frameFeedsTheImportPipeline() throws {
        let analyzer = QRFrameAnalyzer()
        let frame = try makeQRPixelBuffer(payload: MigrationRealVectorTests.aliceURL)
        let payload = try #require(analyzer.payloads(in: frame, now: 1000).first)

        let migration = try MigrationDecoder.decode(payload)
        #expect(migration.accounts.count == 1)
        #expect(migration.accounts.first?.name == "alice@google.com")
    }

    @Test("A plain otpauth QR is decoded out of a frame too")
    func decodesOTPAuthURLFromFrame() throws {
        let url = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        let analyzer = QRFrameAnalyzer()
        let frame = try makeQRPixelBuffer(payload: url)

        #expect(analyzer.payloads(in: frame, now: 1000) == [url])
    }

    @Test("A frame with no QR code yields nothing")
    func blankFrameYieldsNothing() throws {
        let analyzer = QRFrameAnalyzer()
        let frame = try makeBlankPixelBuffer()
        #expect(analyzer.payloads(in: frame, now: 1000).isEmpty)
    }

    /// Analysing every frame would burn CPU for no benefit — a QR held up to a
    /// camera does not change 60 times a second.
    @Test("Frames inside the throttle interval are skipped")
    func throttlesAnalysis() throws {
        let analyzer = QRFrameAnalyzer(minimumInterval: 0.25)
        let frame = try makeQRPixelBuffer(payload: MigrationRealVectorTests.aliceURL)

        #expect(analyzer.payloads(in: frame, now: 100.0).count == 1)

        // A 60 fps camera delivers ~15 frames inside one interval; all skipped.
        for step in 1...14 {
            #expect(analyzer.payloads(in: frame, now: 100.0 + Double(step) * 0.016).isEmpty)
        }

        // Once the interval elapses, analysis resumes.
        #expect(analyzer.payloads(in: frame, now: 100.30).count == 1)
    }

    @Test("The throttle predicate matches the analysis it gates")
    func throttlePredicateAgrees() throws {
        let analyzer = QRFrameAnalyzer(minimumInterval: 0.25)
        let frame = try makeQRPixelBuffer(payload: MigrationRealVectorTests.aliceURL)

        #expect(analyzer.wouldAnalyze(at: 500))
        _ = analyzer.payloads(in: frame, now: 500)

        #expect(!analyzer.wouldAnalyze(at: 500.1))
        #expect(analyzer.wouldAnalyze(at: 500.25))
    }

    /// The still-image path and the camera path must agree, since both feed the
    /// same collector.
    @Test("Still-image decoding agrees with frame decoding")
    func stillImageAgreesWithFrame() throws {
        let payload = MigrationRealVectorTests.aliceURL
        let frame = try makeQRPixelBuffer(payload: payload)

        let fromFrame = QRFrameAnalyzer().payloads(in: frame, now: 1000)

        let context = CIContext()
        let ciImage = CIImage(cvPixelBuffer: frame)
        let cgImage = try #require(context.createCGImage(ciImage, from: ciImage.extent))
        let fromImage = try ImageQRDecoder.payloads(in: cgImage)

        #expect(fromFrame == fromImage)
        #expect(fromImage == [payload])
    }
}
