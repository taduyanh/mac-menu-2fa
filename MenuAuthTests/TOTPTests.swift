import Foundation
import Testing

@testable import MenuAuth

/// RFC 6238 Appendix B. The three secrets differ per algorithm because the
/// spec seeds each HMAC with a key the size of its own block.
private let sha1Secret = Data("12345678901234567890".utf8)
private let sha256Secret = Data("12345678901234567890123456789012".utf8)
private let sha512Secret = Data(
    "1234567890123456789012345678901234567890123456789012345678901234".utf8
)

@Suite("RFC 6238 test vectors")
struct TOTPVectorTests {
    @Test(
        "SHA-1 vectors",
        arguments: [
            (59 as TimeInterval, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ]
    )
    func sha1(time: TimeInterval, expected: String) {
        let actual = TOTP.code(
            secret: sha1Secret,
            at: Date(timeIntervalSince1970: time),
            period: 30,
            digits: 8,
            algorithm: .sha1
        )
        #expect(actual == expected)
    }

    @Test(
        "SHA-256 vectors",
        arguments: [
            (59 as TimeInterval, "46119246"),
            (1_111_111_109, "68084774"),
            (1_111_111_111, "67062674"),
            (1_234_567_890, "91819424"),
            (2_000_000_000, "90698825"),
            (20_000_000_000, "77737706"),
        ]
    )
    func sha256(time: TimeInterval, expected: String) {
        let actual = TOTP.code(
            secret: sha256Secret,
            at: Date(timeIntervalSince1970: time),
            period: 30,
            digits: 8,
            algorithm: .sha256
        )
        #expect(actual == expected)
    }

    @Test(
        "SHA-512 vectors",
        arguments: [
            (59 as TimeInterval, "90693936"),
            (1_111_111_109, "25091201"),
            (1_111_111_111, "99943326"),
            (1_234_567_890, "93441116"),
            (2_000_000_000, "38618901"),
            (20_000_000_000, "47863826"),
        ]
    )
    func sha512(time: TimeInterval, expected: String) {
        let actual = TOTP.code(
            secret: sha512Secret,
            at: Date(timeIntervalSince1970: time),
            period: 30,
            digits: 8,
            algorithm: .sha512
        )
        #expect(actual == expected)
    }

    /// Six digits is what the UI actually renders, and it is the low-order
    /// suffix of the eight-digit vector rather than a separate computation.
    @Test("Six digits is the suffix of the eight-digit vector")
    func sixDigitsTruncatesConsistently() {
        let eight = TOTP.code(
            secret: sha1Secret,
            at: Date(timeIntervalSince1970: 59),
            digits: 8
        )
        let six = TOTP.code(
            secret: sha1Secret,
            at: Date(timeIntervalSince1970: 59),
            digits: 6
        )
        #expect(eight == "94287082")
        #expect(six == "287082")
    }

    /// A code must keep its leading zeros; dropping them is a classic TOTP bug.
    @Test("Leading zeros are preserved")
    func leadingZeros() {
        let code = TOTP.code(
            secret: sha1Secret,
            at: Date(timeIntervalSince1970: 1_111_111_109),
            digits: 8
        )
        #expect(code == "07081804")
        #expect(code.count == 8)
    }
}

@Suite("Time step arithmetic")
struct TOTPCounterTests {
    @Test("Counter is floor(unixTime / period)")
    func counterFloors() {
        #expect(TOTP.counter(at: Date(timeIntervalSince1970: 0), period: 30) == 0)
        #expect(TOTP.counter(at: Date(timeIntervalSince1970: 29), period: 30) == 0)
        #expect(TOTP.counter(at: Date(timeIntervalSince1970: 30), period: 30) == 1)
        #expect(TOTP.counter(at: Date(timeIntervalSince1970: 59), period: 30) == 1)
        #expect(TOTP.counter(at: Date(timeIntervalSince1970: 60), period: 30) == 2)
    }

    /// Large timestamps are where a `Double`-based implementation loses the
    /// exact boundary, so the vector at 20000000000 is checked directly.
    @Test("Counter stays exact at large timestamps")
    func counterExactAtLargeTimes() {
        #expect(
            TOTP.counter(at: Date(timeIntervalSince1970: 20_000_000_000), period: 30)
                == 666_666_666
        )
        #expect(
            TOTP.counter(at: Date(timeIntervalSince1970: 20_000_000_009), period: 30)
                == 666_666_666
        )
        #expect(
            TOTP.counter(at: Date(timeIntervalSince1970: 20_000_000_010), period: 30)
                == 666_666_667
        )
    }

    @Test("Seconds remaining counts down to the next boundary")
    func secondsRemaining() {
        #expect(TOTP.secondsRemaining(at: Date(timeIntervalSince1970: 30), period: 30) == 30)
        #expect(TOTP.secondsRemaining(at: Date(timeIntervalSince1970: 31), period: 30) == 29)
        #expect(TOTP.secondsRemaining(at: Date(timeIntervalSince1970: 59), period: 30) == 1)
        #expect(TOTP.secondsRemaining(at: Date(timeIntervalSince1970: 60), period: 30) == 30)
    }

    /// The counter must change exactly once per period — this is what lets the
    /// UI recompute one HMAC per 30s instead of one per second.
    @Test("Counter changes exactly once per period")
    func counterChangesOncePerPeriod() {
        let base = 1_700_000_000.0
        var changes = 0
        var previous = TOTP.counter(at: Date(timeIntervalSince1970: base), period: 30)
        for offset in 1...90 {
            let next = TOTP.counter(
                at: Date(timeIntervalSince1970: base + Double(offset)),
                period: 30
            )
            if next != previous {
                changes += 1
                previous = next
            }
        }
        #expect(changes == 3)
    }
}

@Suite("Algorithm mapping from the migration payload")
struct OTPAlgorithmTests {
    @Test("Unspecified maps to SHA-1")
    func unspecifiedIsSHA1() {
        #expect(OTPAlgorithm(migrationValue: 0) == .sha1)
        #expect(OTPAlgorithm(migrationValue: 1) == .sha1)
    }

    @Test("Known algorithms map through")
    func knownAlgorithms() {
        #expect(OTPAlgorithm(migrationValue: 2) == .sha256)
        #expect(OTPAlgorithm(migrationValue: 3) == .sha512)
    }

    @Test("MD5 and unknown values are refused")
    func unsupportedAlgorithms() {
        #expect(OTPAlgorithm(migrationValue: 4) == nil)
        #expect(OTPAlgorithm(migrationValue: 99) == nil)
    }
}
