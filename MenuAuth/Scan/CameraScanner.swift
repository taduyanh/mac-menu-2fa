import AVFoundation
import Observation

/// Live QR scanning for pointing the Mac's camera at the phone's export screen.
///
/// Frames go to `AVCaptureVideoDataOutput` and are decoded by Vision rather than
/// by `AVCaptureMetadataOutput`. The metadata path is the conventional one on
/// iOS, but on macOS it reported no QR support and the scanner dead-ended; see
/// `QRFrameAnalyzer`.
///
/// The session is built when the Camera tab appears and fully torn down when it
/// goes away — an idle `AVCaptureSession` is by far the most expensive thing
/// this app could leave running.
@Observable
final class CameraScanner: NSObject {
    enum State: Equatable {
        case idle
        case starting
        case running
        case permissionDenied
        case unavailable(String)
    }

    private(set) var state: State = .idle

    /// Called on the main actor for every decoded payload, including repeats —
    /// de-duplication is `BatchCollector`'s job.
    @ObservationIgnored var onPayload: ((String) -> Void)?

    @ObservationIgnored private(set) var session: AVCaptureSession?
    /// `startRunning()` blocks; it must never be called on the main thread.
    @ObservationIgnored private let sessionQueue = DispatchQueue(
        label: "com.anhtd.MenuAuth.camera",
        qos: .userInitiated
    )
    /// Touched only from `sessionQueue`, so it must not inherit the main-actor
    /// isolation this target applies by default.
    @ObservationIgnored nonisolated private let analyzer = QRFrameAnalyzer()

    func start() async {
        switch state {
        case .running, .starting: return
        case .idle, .permissionDenied, .unavailable: break
        }
        state = .starting

        guard await requestAccess() else {
            state = .permissionDenied
            return
        }
        guard let device = AVCaptureDevice.default(for: .video) else {
            state = .unavailable("No camera was found on this Mac.")
            return
        }

        let session = AVCaptureSession()
        session.beginConfiguration()
        // 720p is ample for reading a QR held up to the camera, and is several
        // times cheaper to move and analyse than the default full resolution.
        session.sessionPreset = session.canSetSessionPreset(.hd1280x720) ? .hd1280x720 : .high

        do {
            let input = try AVCaptureDeviceInput(device: device)
            guard session.canAddInput(input) else {
                session.commitConfiguration()
                state = .unavailable(Self.fallbackAdvice("This Mac's camera couldn't be opened."))
                return
            }
            session.addInput(input)
        } catch {
            session.commitConfiguration()
            state = .unavailable(Self.fallbackAdvice(error.localizedDescription))
            return
        }

        let output = AVCaptureVideoDataOutput()
        output.alwaysDiscardsLateVideoFrames = true
        output.videoSettings = [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA
        ]
        guard session.canAddOutput(output) else {
            session.commitConfiguration()
            state = .unavailable(Self.fallbackAdvice("This Mac's camera couldn't be read."))
            return
        }
        session.addOutput(output)
        output.setSampleBufferDelegate(self, queue: sessionQueue)
        session.commitConfiguration()

        self.session = session
        state = .running
        sessionQueue.async { session.startRunning() }
    }

    /// Tears the session down rather than merely pausing it, so memory returns
    /// to baseline when the import view closes.
    func stop() {
        guard let session else {
            state = .idle
            return
        }
        self.session = nil
        state = .idle
        sessionQueue.async {
            if session.isRunning { session.stopRunning() }
            for output in session.outputs {
                (output as? AVCaptureVideoDataOutput)?.setSampleBufferDelegate(nil, queue: nil)
                session.removeOutput(output)
            }
            for input in session.inputs { session.removeInput(input) }
        }
    }

    isolated deinit {
        stop()
    }

    /// Every camera failure has two working alternatives, so say so rather than
    /// leaving the user at a dead end.
    private static func fallbackAdvice(_ reason: String) -> String {
        reason + " Use the Screen or Image tab instead."
    }

    private func requestAccess() async -> Bool {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized: true
        case .notDetermined: await AVCaptureDevice.requestAccess(for: .video)
        default: false
        }
    }
}

extension CameraScanner: AVCaptureVideoDataOutputSampleBufferDelegate {
    /// Called on `sessionQueue` for every frame; `analyzer` throttles the
    /// expensive part down to a few looks per second.
    nonisolated func captureOutput(
        _ output: AVCaptureOutput,
        didOutput sampleBuffer: CMSampleBuffer,
        from connection: AVCaptureConnection
    ) {
        guard let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        let payloads = analyzer.payloads(in: pixelBuffer)
        guard !payloads.isEmpty else { return }

        Task { @MainActor [weak self] in
            guard let self, let handler = self.onPayload else { return }
            for payload in payloads { handler(payload) }
        }
    }
}
