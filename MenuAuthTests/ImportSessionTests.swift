import Foundation
import Testing

@testable import MenuAuth

@Suite("Import session", .serialized)
@MainActor
struct ImportSessionTests {
    /// Builds a migration URL for one fragment of a multi-QR export.
    private func fragmentURL(
        index: UInt64,
        size: UInt64,
        batchID: UInt64,
        names: [String]
    ) -> String {
        ProtoWriter.migrationURL(
            ProtoWriter.migrationPayload(
                entries: names.map {
                    (Data("secret-\($0)".utf8), $0, "Issuer", 1, 1, 2)
                },
                batchSize: size,
                batchIndex: index,
                batchID: batchID
            )
        )
    }

    @Test("A single-fragment export is immediately ready to commit")
    func singleFragmentCommits() {
        let session = ImportSession()
        #expect(session.accept(MigrationRealVectorTests.aliceURL))
        #expect(session.isComplete)
        #expect(session.accounts.count == 1)
    }

    /// The behaviour this whole type exists for: a partly-scanned export has to
    /// still be there after the panel is dismissed and reopened.
    @Test("A partial batch is retained so the panel can be reopened")
    func partialBatchSurvives() {
        let session = ImportSession()

        #expect(!session.accept(fragmentURL(index: 0, size: 3, batchID: 9, names: ["a"])))
        #expect(session.isInProgress)
        #expect(!session.isComplete)
        #expect(session.progressDescription == "1 of 3")
        #expect(session.nextMissingFragment == 2)

        // Simulates the user clicking away to swipe the phone and coming back:
        // nothing here is tied to the view's lifetime.
        #expect(!session.accept(fragmentURL(index: 1, size: 3, batchID: 9, names: ["b"])))
        #expect(session.progressDescription == "2 of 3")

        #expect(session.accept(fragmentURL(index: 2, size: 3, batchID: 9, names: ["c"])))
        #expect(session.isComplete)
        #expect(session.accounts.map(\.name) == ["a", "b", "c"])
    }

    /// Pressing Capture twice on the same screen must not double-import or
    /// raise an error.
    @Test("Recapturing the same QR is silent")
    func recaptureIsSilent() {
        let session = ImportSession()
        let fragment = fragmentURL(index: 0, size: 2, batchID: 9, names: ["a"])

        _ = session.accept(fragment)
        session.statusMessage = nil

        #expect(!session.accept(fragment))
        #expect(session.errorMessage == nil)
        #expect(session.statusMessage == nil)
        #expect(session.accounts.count == 1)
    }

    @Test("A QR from a different export is reported")
    func differentExportIsReported() {
        let session = ImportSession()
        _ = session.accept(fragmentURL(index: 0, size: 3, batchID: 9, names: ["a"]))
        _ = session.accept(fragmentURL(index: 1, size: 3, batchID: 77, names: ["x"]))

        #expect(session.errorMessage == ImportError.mismatchedBatch.localizedDescription)
        #expect(session.accounts.map(\.name) == ["a"])
    }

    @Test("An unrelated QR is named when nothing has been scanned yet")
    func unrelatedQRIsReported() {
        let session = ImportSession()
        #expect(!session.accept("WIFI:S:MyNetwork;T:WPA;P:hunter2;;"))
        #expect(session.errorMessage != nil)
        #expect(!session.isInProgress)
    }

    /// Mid-batch, a stray code in shot must not overwrite the "swipe to QR 2"
    /// prompt with an error.
    @Test("An unrelated QR is ignored mid-batch")
    func unrelatedQRIgnoredMidBatch() {
        let session = ImportSession()
        _ = session.accept(fragmentURL(index: 0, size: 3, batchID: 9, names: ["a"]))
        session.errorMessage = nil

        #expect(!session.accept("https://example.com"))
        #expect(session.errorMessage == nil)
        #expect(session.progressDescription == "1 of 3")
    }

    @Test("A plain otpauth QR is accepted too")
    func acceptsSingleOTPAuthURL() {
        let session = ImportSession()
        #expect(session.accept(
            "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        ))
        #expect(session.accounts.first?.name == "alice@google.com")
    }

    @Test("Reset clears everything, and the same export can be scanned again")
    func resetClears() {
        let session = ImportSession()
        _ = session.accept(fragmentURL(index: 0, size: 3, batchID: 9, names: ["a"]))
        session.errorMessage = "stale"
        session.reset()

        #expect(!session.isInProgress)
        #expect(session.accounts.isEmpty)
        #expect(session.errorMessage == nil)
        #expect(session.statusMessage == nil)

        // And a re-scan after reset is accepted rather than swallowed as a dupe.
        #expect(!session.accept(fragmentURL(index: 0, size: 3, batchID: 9, names: ["a"])))
        #expect(session.isInProgress)
    }

    @Test("Skipped entries carry through to the store")
    func skippedCountCarries() throws {
        let session = ImportSession()
        let url = ProtoWriter.migrationURL(
            ProtoWriter.migrationPayload(entries: [
                (Data("aaaaaaaaaa".utf8), "good", "Issuer", 1, 1, 2),
                (Data("bbbbbbbbbb".utf8), "hotp", "Issuer", 1, 1, 1),
            ])
        )
        #expect(session.accept(url))
        #expect(session.accounts.count == 1)
        #expect(session.skippedCount == 1)
    }

    @Test("The source selection defaults to the camera")
    func defaultSource() {
        #expect(ImportSession().source == .camera)
        #expect(ImportSession.Source.allCases.count == 3)
    }
}

@Suite("Screen capture availability")
struct ScreenQRCaptureTests {
    /// Must not prompt, so it is safe to call while drawing the import view.
    @Test("Checking permission is non-prompting and does not crash")
    func permissionCheckIsSafe() {
        _ = ScreenQRCapture.hasPermission
    }

    @Test("Failures carry an actionable message")
    func failuresExplainThemselves() {
        #expect(
            ScreenQRCapture.Failure.permissionDenied.errorDescription?
                .contains("Screen Recording") == true
        )
        #expect(
            ScreenQRCapture.Failure.noQRCodeFound.errorDescription?
                .contains("iPhone Mirroring") == true
        )
    }
}
