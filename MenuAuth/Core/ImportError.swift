import Foundation

/// Failures that reach the import sheet. Every message is written to tell the
/// user what to do next, because they surface while they are holding a phone up
/// to the camera.
nonisolated enum ImportError: Error, LocalizedError, Equatable {
    case notAMigrationURL
    case unrecognizedQRCode
    case missingDataParameter
    case malformedDataParameter
    case malformedPayload
    case noAccountsInPayload
    case unsupportedOTPType
    case missingSecret
    case invalidSecretEncoding
    case mismatchedBatch

    var errorDescription: String? {
        switch self {
        case .notAMigrationURL:
            "That QR code isn't a Google Authenticator export."
        case .unrecognizedQRCode:
            "That QR code isn't an authenticator code. In Google Authenticator, "
                + "tap the ⋯ menu and choose Transfer accounts → Export accounts."
        case .missingDataParameter:
            "The export QR code is missing its data. Try exporting again."
        case .malformedDataParameter:
            "The export data couldn't be read. Try exporting again from your phone."
        case .malformedPayload:
            "The export data is damaged. If you scanned a photo, try a sharper image."
        case .noAccountsInPayload:
            "That export doesn't contain any accounts."
        case .unsupportedOTPType:
            "That account uses a counter-based code, which MenuAuth doesn't support yet."
        case .missingSecret:
            "That account is missing its secret key."
        case .invalidSecretEncoding:
            "The secret key isn't valid base32."
        case .mismatchedBatch:
            "That QR code is from a different export. Start over and scan the "
                + "codes from a single export."
        }
    }
}
