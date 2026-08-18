import Foundation

/// Assembles a Google Authenticator export that spans several QR codes.
///
/// Two realities drive this design:
/// - Google splits an export into `batch_size` fragments once you have more
///   than a few accounts, and you must scan each one.
/// - A live camera decodes the *same* QR dozens of times per second, so
///   re-submitting a fragment must be a no-op rather than a duplicate import.
nonisolated struct BatchCollector: Sendable {
    enum Outcome: Equatable {
        /// A new fragment was absorbed, adding this many accounts.
        case accepted(newAccounts: Int)
        /// The same fragment as before — the camera is still pointed at it.
        case alreadyScanned
        /// A fragment from a different export; the user changed screens midway.
        case differentExport
    }

    private(set) var batchID: Int?
    private(set) var expectedFragments = 1
    private(set) var scannedIndices: Set<Int> = []
    private(set) var accounts: [ImportedAccount] = []
    private(set) var skippedCount = 0

    private var seenKeys: Set<String> = []

    var isComplete: Bool {
        guard batchID != nil else { return !accounts.isEmpty }
        return scannedIndices.count >= expectedFragments
    }

    var isEmpty: Bool { accounts.isEmpty }

    /// "2 of 3" — shown live while the user swipes through the export screens.
    var progressDescription: String {
        "\(scannedIndices.count) of \(expectedFragments)"
    }

    /// Which fragment to ask for next, 1-based for display.
    var nextMissingFragment: Int? {
        guard !isComplete else { return nil }
        return (0..<expectedFragments).first { !scannedIndices.contains($0) }.map { $0 + 1 }
    }

    mutating func accept(_ payload: MigrationPayload) -> Outcome {
        if let batchID {
            // A single-fragment export carries batch_id 0 and is unambiguous;
            // only enforce identity once a real multi-fragment batch is running.
            guard payload.batchID == batchID else { return .differentExport }
        } else {
            batchID = payload.batchID
            expectedFragments = max(payload.batchSize, 1)
        }

        guard !scannedIndices.contains(payload.batchIndex) else { return .alreadyScanned }
        scannedIndices.insert(payload.batchIndex)
        skippedCount += payload.skippedCount

        return .accepted(newAccounts: absorb(payload.accounts))
    }

    /// A plain `otpauth://` QR: one account, no batch semantics.
    mutating func accept(_ account: ImportedAccount) -> Outcome {
        guard !seenKeys.contains(account.dedupeKey) else { return .alreadyScanned }
        return .accepted(newAccounts: absorb([account]))
    }

    mutating func accept(_ payload: QRPayload) -> Outcome {
        switch payload {
        case .migration(let migration): accept(migration)
        case .single(let account): accept(account)
        }
    }

    mutating func reset() {
        self = BatchCollector()
    }

    /// Adds accounts not already collected. Two fragments of one export never
    /// overlap, but a user rescanning a *previous* export into the same session
    /// would otherwise produce duplicate rows.
    private mutating func absorb(_ incoming: [ImportedAccount]) -> Int {
        var added = 0
        for account in incoming where !seenKeys.contains(account.dedupeKey) {
            seenKeys.insert(account.dedupeKey)
            accounts.append(account)
            added += 1
        }
        return added
    }
}
