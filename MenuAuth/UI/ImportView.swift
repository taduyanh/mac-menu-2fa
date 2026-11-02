import AVFoundation
import SwiftUI
import UniformTypeIdentifiers

/// Bringing accounts over from the phone, by whichever route suits: the Mac's
/// camera, a QR already visible on screen, or a saved image.
struct ImportView: View {
    @Binding var route: MenuPanel.Route
    @Environment(AccountStore.self) private var store
    @Environment(ImportSession.self) private var session

    @State private var scanner = CameraScanner()
    @State private var isChoosingFile = false
    /// Stops a second commit starting while the first is waiting on Touch ID.
    @State private var isCommitting = false
    /// Read once rather than from `body`: a TCC lookup on every re-render would
    /// be needless work, and the answer cannot change while the panel is open.
    @State private var hasScreenPermission = ScreenQRCapture.hasPermission

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            sourcePicker

            sourceArea
                .frame(height: 176)
                .frame(maxWidth: .infinity)
                .background(.black.opacity(session.source == .camera ? 0.85 : 0.06))

            VStack(alignment: .leading, spacing: 8) {
                instructions

                if let statusMessage = session.statusMessage {
                    Label(statusMessage, systemImage: "checkmark.circle.fill")
                        .font(.caption)
                        .foregroundStyle(.green)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let errorMessage = session.errorMessage {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }

                actions
            }
            .padding(12)
        }
        // The camera is started and torn down as the selected source changes,
        // so choosing Screen or Image never spins it up at all.
        .task(id: session.source) { await syncCamera() }
        .onDisappear { scanner.stop() }
        .dropDestination(for: URL.self) { urls, _ in
            guard let url = urls.first else { return false }
            session.source = .image
            importImage(at: url)
            return true
        }
        .fileImporter(
            isPresented: $isChoosingFile,
            allowedContentTypes: [.image],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                if let url = urls.first { importImage(at: url) }
            case .failure(let error):
                session.errorMessage = error.localizedDescription
            }
        }
    }

    // MARK: - Chrome

    private var header: some View {
        HStack {
            Button {
                route = .list
            } label: {
                Label("Back", systemImage: "chevron.left")
                    .font(.system(size: 12))
            }
            .buttonStyle(.plain)

            Spacer()
            Text("Add accounts").font(.system(size: 12, weight: .semibold))
            Spacer()

            if session.isInProgress {
                Button("Reset") { session.reset() }
                    .font(.system(size: 11))
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
            } else {
                // Keeps the title optically centred against the back button.
                Color.clear.frame(width: 44, height: 1)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private var sourcePicker: some View {
        @Bindable var session = session
        return Picker("Source", selection: $session.source) {
            ForEach(ImportSession.Source.allCases) { source in
                Label(source.title, systemImage: source.symbol).tag(source)
            }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .padding(.horizontal, 12)
        .padding(.bottom, 8)
    }

    @ViewBuilder
    private var sourceArea: some View {
        switch session.source {
        case .camera: cameraArea
        case .screen: screenArea
        case .image: imageArea
        }
    }

    @ViewBuilder
    private var cameraArea: some View {
        switch scanner.state {
        case .running:
            CameraPreview(session: scanner.session)
        case .starting, .idle:
            placeholder("Starting camera…", systemImage: "camera", onDark: true)
        case .permissionDenied:
            placeholder(
                "Camera access is off. Enable it in System Settings ▸ Privacy & Security ▸ "
                    + "Camera, or use the Screen or Image tabs instead.",
                systemImage: "camera.badge.ellipsis",
                onDark: true
            )
        case .unavailable(let reason):
            placeholder(reason, systemImage: "exclamationmark.triangle", onDark: true)
        }
    }

    private var screenArea: some View {
        VStack(spacing: 10) {
            Image(systemName: "macwindow.on.rectangle")
                .font(.system(size: 26, weight: .light))
                .foregroundStyle(.secondary)

            Text("Show the export QR anywhere on screen — an iPhone Mirroring window "
                + "works well — then capture it.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)

            Button {
                Task { await captureScreen() }
            } label: {
                if session.isCapturing {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Capture Screen", systemImage: "camera.viewfinder")
                }
            }
            .controlSize(.regular)
            .buttonStyle(.borderedProminent)
            .disabled(session.isCapturing)

            if !hasScreenPermission {
                Text("Needs Screen Recording permission.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(16)
    }

    private var imageArea: some View {
        VStack(spacing: 10) {
            Image(systemName: "photo.on.rectangle.angled")
                .font(.system(size: 26, weight: .light))
                .foregroundStyle(.secondary)
            Text("Drop a screenshot or photo of the export QR here, choose a file, "
                + "or paste one.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(16)
    }

    private func placeholder(
        _ text: String,
        systemImage: String,
        onDark: Bool = false
    ) -> some View {
        VStack(spacing: 8) {
            Image(systemName: systemImage)
                .font(.system(size: 22, weight: .light))
            Text(text)
                .font(.caption)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .foregroundStyle(onDark ? AnyShapeStyle(.white.opacity(0.75)) : AnyShapeStyle(.secondary))
        .padding(16)
    }

    @ViewBuilder
    private var instructions: some View {
        if !session.isInProgress {
            Text("In Google Authenticator: ⋯ → Transfer accounts → Export accounts.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        } else if !session.isComplete, let next = session.nextMissingFragment {
            // The part most third-party importers get wrong: a large export is
            // several QR codes and the user has to be told to swipe.
            Label(
                "Scanned \(session.progressDescription). Swipe to QR code \(next) on your "
                    + "phone, then capture again.",
                systemImage: "arrow.right.circle"
            )
            .font(.caption)
            .foregroundStyle(.blue)
            .fixedSize(horizontal: false, vertical: true)
        } else {
            Text("Ready to import \(session.accounts.count) "
                + "account\(session.accounts.count == 1 ? "" : "s").")
                .font(.caption)
                .foregroundStyle(.secondary)
        }

        let overwrites = store.overwriteCount(for: session.accounts)
        if overwrites > 0 {
            Label(
                "\(overwrites) of these already exist and importing will replace "
                    + "\(overwrites == 1 ? "its" : "their") secret. Only continue if you "
                    + "scanned this code from your own phone.",
                systemImage: "exclamationmark.triangle.fill"
            )
            .font(.caption)
            .foregroundStyle(.orange)
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var actions: some View {
        HStack(spacing: 8) {
            Button("Choose Image…") { isChoosingFile = true }
                .controlSize(.small)
            Button("Paste") { importFromClipboard() }
                .controlSize(.small)
            Spacer()
            if session.isInProgress {
                Button("Import \(session.accounts.count)") { commit() }
                    .controlSize(.small)
                    .buttonStyle(.borderedProminent)
            }
        }
    }

    // MARK: - Sources

    /// Keeps the capture session in step with the selected tab, so the camera
    /// only ever runs while its own tab is showing.
    private func syncCamera() async {
        if session.source == .camera {
            scanner.onPayload = { payload in absorb(payload) }
            await scanner.start()
        } else {
            scanner.stop()
        }
    }

    private func captureScreen() async {
        session.isCapturing = true
        session.errorMessage = nil
        defer { session.isCapturing = false }

        do {
            let payloads = try await ScreenQRCapture.capturePayloads()
            for payload in payloads { absorb(payload) }
        } catch {
            session.errorMessage = error.localizedDescription
            // A first press is what triggers the system prompt; re-read so the
            // hint disappears once the user grants it.
            hasScreenPermission = ScreenQRCapture.hasPermission
        }
    }

    private func importImage(at url: URL) {
        do {
            let payloads = try ImageQRDecoder.payloads(at: url)
            session.errorMessage = nil
            for payload in payloads { absorb(payload) }
        } catch {
            session.errorMessage = error.localizedDescription
        }
    }

    private func importFromClipboard() {
        let pasteboard = NSPasteboard.general

        if let text = pasteboard.string(forType: .string),
           MigrationDecoder.canDecode(text) || OTPAuthURL.canDecode(text) {
            absorb(text)
            return
        }
        if let data = pasteboard.data(forType: .tiff) ?? pasteboard.data(forType: .png) {
            do {
                let payloads = try ImageQRDecoder.payloads(in: data)
                session.errorMessage = nil
                for payload in payloads { absorb(payload) }
            } catch {
                session.errorMessage = error.localizedDescription
            }
            return
        }
        session.errorMessage = "The clipboard doesn't contain a QR code image or an otpauth link."
    }

    private func absorb(_ payload: String) {
        // A complete export commits itself; a partial one waits for the rest.
        // Unless it would replace an account that already exists: a QR is
        // untrusted, so overwriting a secret needs a deliberate click.
        if session.accept(payload), store.overwriteCount(for: session.accounts) == 0 {
            commit()
        }
    }

    private func commit() {
        guard session.isInProgress, !isCommitting else { return }
        isCommitting = true
        Task {
            defer { isCommitting = false }
            // A no-op when already unlocked; otherwise the one prompt, which
            // the vault then reuses for the write.
            guard await store.unlock() else {
                session.errorMessage = "Unlock to finish importing."
                return
            }
            let summary = store.importAccounts(session.accounts, skipped: session.skippedCount)
            scanner.stop()
            session.reset()
            session.statusMessage = summary.description
            route = .list
        }
    }
}

/// Hosts the capture preview layer. Kept as the view's backing layer so AppKit
/// resizes it, rather than managing frames by hand.
private struct CameraPreview: NSViewRepresentable {
    let session: AVCaptureSession?

    func makeNSView(context: Context) -> PreviewView {
        let view = PreviewView()
        view.session = session
        return view
    }

    func updateNSView(_ nsView: PreviewView, context: Context) {
        nsView.session = session
    }

    final class PreviewView: NSView {
        private let previewLayer = AVCaptureVideoPreviewLayer()

        var session: AVCaptureSession? {
            get { previewLayer.session }
            set { previewLayer.session = newValue }
        }

        override init(frame frameRect: NSRect) {
            super.init(frame: frameRect)
            previewLayer.videoGravity = .resizeAspectFill
            wantsLayer = true
            layer = previewLayer
        }

        @available(*, unavailable)
        required init?(coder: NSCoder) { fatalError("not used from a nib") }
    }
}
