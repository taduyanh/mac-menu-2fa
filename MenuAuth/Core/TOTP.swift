import CryptoKit
import Foundation

/// Hash function backing the HMAC in RFC 4226 / RFC 6238.
///
/// SHA-1 is the TOTP default and remains the only algorithm most issuers emit.
/// Its use here is not a weakness: HMAC-SHA1 does not rely on collision
/// resistance, which is the property SHA-1 lost.
nonisolated enum OTPAlgorithm: String, Codable, Sendable, CaseIterable {
    case sha1
    case sha256
    case sha512

    /// Maps the `Algorithm` enum used by Google Authenticator's export payload.
    /// `0` means unspecified, which the reference implementation treats as SHA-1.
    init?(migrationValue: UInt64) {
        switch migrationValue {
        case 0, 1: self = .sha1
        case 2: self = .sha256
        case 3: self = .sha512
        default: return nil // 4 == MD5, which no real issuer uses and we refuse
        }
    }
}

nonisolated enum TOTP {
    static let defaultPeriod = 30
    static let defaultDigits = 6

    /// The RFC 6238 time step: `floor(unixTime / period)`.
    ///
    /// Computed in integer arithmetic rather than by dividing the `Double` from
    /// `timeIntervalSince1970`, so the step boundary is exact.
    static func counter(at date: Date, period: Int) -> UInt64 {
        precondition(period > 0, "period must be positive")
        let seconds = Int64(date.timeIntervalSince1970.rounded(.down))
        guard seconds > 0 else { return 0 }
        return UInt64(seconds / Int64(period))
    }

    /// Seconds until the current time step ends — what the countdown ring shows.
    static func secondsRemaining(at date: Date, period: Int) -> Int {
        precondition(period > 0, "period must be positive")
        let seconds = Int64(date.timeIntervalSince1970.rounded(.down))
        guard seconds > 0 else { return period }
        return period - Int(seconds % Int64(period))
    }

    /// RFC 4226 dynamic truncation over an HMAC of the big-endian counter.
    static func code(
        secret: Data,
        counter: UInt64,
        digits: Int = defaultDigits,
        algorithm: OTPAlgorithm = .sha1
    ) -> String {
        var bigEndianCounter = counter.bigEndian
        let message = withUnsafeBytes(of: &bigEndianCounter) { Data($0) }
        let key = SymmetricKey(data: secret)

        let mac: Data = switch algorithm {
        case .sha1: Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256: Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512: Data(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }

        // `mac` is a fresh Data with a zero-based index, so subscripting is safe.
        let offset = Int(mac[mac.count - 1] & 0x0f)
        let truncated = (UInt32(mac[offset] & 0x7f) << 24)
            | (UInt32(mac[offset + 1]) << 16)
            | (UInt32(mac[offset + 2]) << 8)
            | UInt32(mac[offset + 3])

        let value = truncated % modulus(forDigits: digits)
        return String(format: "%0\(clampedDigits(digits))u", value)
    }

    static func code(
        secret: Data,
        at date: Date,
        period: Int = defaultPeriod,
        digits: Int = defaultDigits,
        algorithm: OTPAlgorithm = .sha1
    ) -> String {
        code(
            secret: secret,
            counter: counter(at: date, period: period),
            digits: digits,
            algorithm: algorithm
        )
    }

    /// A lookup rather than `pow()`: this runs on every code refresh and
    /// `pow` returns a `Double`, which would round wrong at 8 digits.
    private static func modulus(forDigits digits: Int) -> UInt32 {
        switch clampedDigits(digits) {
        case 6: 1_000_000
        case 7: 10_000_000
        default: 100_000_000
        }
    }

    private static func clampedDigits(_ digits: Int) -> Int {
        min(max(digits, 6), 8)
    }
}
