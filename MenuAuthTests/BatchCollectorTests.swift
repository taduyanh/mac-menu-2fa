import Foundation
import Testing

@testable import MenuAuth

@Suite("Multi-QR batch assembly")
struct BatchCollectorTests {
    private func fragment(
        index: Int,
        size: Int,
        batchID: Int,
        names: [String]
    ) -> MigrationPayload {
        MigrationPayload(
            accounts: names.map {
                ImportedAccount(issuer: "Issuer", name: $0, secret: Data($0.utf8))
            },
            batchSize: size,
            batchIndex: index,
            batchID: batchID,
            skippedCount: 0
        )
    }

    @Test("A single-fragment export completes immediately")
    func singleFragmentCompletes() {
        var collector = BatchCollector()
        let outcome = collector.accept(fragment(index: 0, size: 1, batchID: 0, names: ["a", "b"]))

        #expect(outcome == .accepted(newAccounts: 2))
        #expect(collector.isComplete)
        #expect(collector.accounts.count == 2)
        #expect(collector.progressDescription == "1 of 1")
    }

    @Test("A three-fragment export completes only after all three")
    func multiFragmentNeedsAll() {
        var collector = BatchCollector()

        #expect(collector.accept(fragment(index: 0, size: 3, batchID: 7, names: ["a"]))
            == .accepted(newAccounts: 1))
        #expect(!collector.isComplete)
        #expect(collector.progressDescription == "1 of 3")
        #expect(collector.nextMissingFragment == 2)

        #expect(collector.accept(fragment(index: 1, size: 3, batchID: 7, names: ["b"]))
            == .accepted(newAccounts: 1))
        #expect(!collector.isComplete)

        #expect(collector.accept(fragment(index: 2, size: 3, batchID: 7, names: ["c"]))
            == .accepted(newAccounts: 1))
        #expect(collector.isComplete)
        #expect(collector.accounts.map(\.name) == ["a", "b", "c"])
        #expect(collector.nextMissingFragment == nil)
    }

    @Test("Fragments may arrive in any order")
    func acceptsOutOfOrderFragments() {
        var collector = BatchCollector()
        _ = collector.accept(fragment(index: 2, size: 3, batchID: 7, names: ["c"]))
        _ = collector.accept(fragment(index: 0, size: 3, batchID: 7, names: ["a"]))
        #expect(collector.nextMissingFragment == 2)
        _ = collector.accept(fragment(index: 1, size: 3, batchID: 7, names: ["b"]))

        #expect(collector.isComplete)
        #expect(Set(collector.accounts.map(\.name)) == ["a", "b", "c"])
    }

    /// A live camera decodes the same QR many times per second. Without this,
    /// holding steady for one second would import an account dozens of times.
    @Test("Rescanning the same fragment is a no-op")
    func repeatedScansAreIgnored() {
        var collector = BatchCollector()
        let first = fragment(index: 0, size: 2, batchID: 7, names: ["a"])

        #expect(collector.accept(first) == .accepted(newAccounts: 1))
        for _ in 0..<30 {
            #expect(collector.accept(first) == .alreadyScanned)
        }
        #expect(collector.accounts.count == 1)
        #expect(collector.progressDescription == "1 of 2")
    }

    @Test("A fragment from another export is rejected")
    func rejectsDifferentExport() {
        var collector = BatchCollector()
        _ = collector.accept(fragment(index: 0, size: 3, batchID: 7, names: ["a"]))

        #expect(collector.accept(fragment(index: 1, size: 3, batchID: 99, names: ["x"]))
            == .differentExport)
        #expect(collector.accounts.map(\.name) == ["a"])
        #expect(collector.progressDescription == "1 of 3")
    }

    /// Two fragments of one export never share accounts, but rescanning an
    /// older export into the same session would otherwise duplicate rows.
    @Test("Duplicate accounts across fragments are collapsed")
    func deduplicatesAccounts() {
        var collector = BatchCollector()
        _ = collector.accept(fragment(index: 0, size: 2, batchID: 7, names: ["a", "b"]))

        #expect(collector.accept(fragment(index: 1, size: 2, batchID: 7, names: ["b", "c"]))
            == .accepted(newAccounts: 1))
        #expect(collector.accounts.map(\.name) == ["a", "b", "c"])
    }

    @Test("Skipped-entry counts accumulate across fragments")
    func accumulatesSkippedCounts() {
        var collector = BatchCollector()
        var first = fragment(index: 0, size: 2, batchID: 7, names: ["a"])
        first.skippedCount = 2
        var second = fragment(index: 1, size: 2, batchID: 7, names: ["b"])
        second.skippedCount = 3

        _ = collector.accept(first)
        _ = collector.accept(second)
        #expect(collector.skippedCount == 5)
    }

    @Test("Single otpauth accounts collect alongside batches")
    func acceptsSingleAccounts() {
        var collector = BatchCollector()
        let account = ImportedAccount(issuer: "GitHub", name: "anhtd", secret: Data("s".utf8))

        #expect(collector.accept(account) == .accepted(newAccounts: 1))
        #expect(collector.accept(account) == .alreadyScanned)
        #expect(collector.isComplete)
        #expect(collector.accounts.count == 1)
    }

    @Test("Reset clears everything")
    func resetClears() {
        var collector = BatchCollector()
        _ = collector.accept(fragment(index: 0, size: 3, batchID: 7, names: ["a"]))
        collector.reset()

        #expect(collector.isEmpty)
        #expect(collector.batchID == nil)
        #expect(collector.expectedFragments == 1)
        #expect(collector.scannedIndices.isEmpty)
        #expect(collector.skippedCount == 0)
    }

    /// After a reset the same export must be re-importable — otherwise the
    /// dedupe set silently swallows a retry.
    @Test("The same export can be scanned again after a reset")
    func reimportAfterReset() {
        var collector = BatchCollector()
        let only = fragment(index: 0, size: 1, batchID: 7, names: ["a"])
        _ = collector.accept(only)
        collector.reset()

        #expect(collector.accept(only) == .accepted(newAccounts: 1))
    }
}
