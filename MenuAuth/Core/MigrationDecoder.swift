import Foundation

/// One decoded `otpauth-migration://offline?data=...` QR code.
///
/// Google splits an export across several QR codes once you have more than a
/// handful of accounts, so a single scan is usually a *fragment*: the batch
/// fields are what let `BatchCollector` tell whether more remain.
nonisolated struct MigrationPayload: Sendable, Equatable {
    var accounts: [ImportedAccount]
    var batchSize: Int
    var batchIndex: Int
    var batchID: Int
    /// Entries dropped because they were HOTP or used an algorithm we refuse.
    /// Surfaced in the UI rather than silently discarded.
    var skippedCount: Int

    var isSingleFragment: Bool { batchSize <= 1 }
}

nonisolated enum MigrationDecoder {
    static let scheme = "otpauth-migration"

    /// Google Authenticator has no period field in its payload — the app is
    /// hardcoded to 30-second steps, so every imported account uses that.
    private static let googleAuthenticatorPeriod = 30

    /// Bounds on untrusted input. A QR code holds under 3 KB and a real export
    /// fragment well under that, so these are generous for genuine data while
    /// stopping a hostile clipboard string or crafted payload from making the
    /// decoder allocate without limit.
    static let maximumInputLength = 16_384
    static let maximumAccountsPerPayload = KeychainStore.maximumAccounts
    static let maximumSecretLength = 1_024
    static let maximumBatchSize = 255

    static func canDecode(_ text: String) -> Bool {
        text.lowercased().hasPrefix(scheme + "://")
    }

    /// Full pipeline: URL string → percent-decode → base64 → protobuf.
    static func decode(_ text: String) throws -> MigrationPayload {
        let base64 = try extractDataParameter(from: text)
        let payload = try decodeBase64(base64)
        return try decode(protobuf: payload)
    }

    // MARK: - URL handling

    /// Deliberately does not use `URL`/`URLComponents`.
    ///
    /// The `data` value is standard base64, so it contains `+`, `/` and `=`.
    /// Query parsers that apply form-decoding turn `+` into a space, which
    /// corrupts the payload into something that still base64-decodes but
    /// yields garbage secrets. Extracting the raw substring and percent-decoding
    /// it explicitly is the only way to be sure.
    static func extractDataParameter(from text: String) throws -> String {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard canDecode(trimmed) else { throw ImportError.notAMigrationURL }
        guard trimmed.utf8.count <= maximumInputLength else {
            throw ImportError.malformedDataParameter
        }
        guard let queryStart = trimmed.firstIndex(of: "?") else {
            throw ImportError.missingDataParameter
        }

        let query = trimmed[trimmed.index(after: queryStart)...]
        for pair in query.split(separator: "&", omittingEmptySubsequences: true) {
            guard let equals = pair.firstIndex(of: "=") else { continue }
            let key = pair[..<equals]
            guard key.lowercased() == "data" else { continue }

            let rawValue = String(pair[pair.index(after: equals)...])
            guard let decoded = rawValue.removingPercentEncoding else {
                throw ImportError.malformedDataParameter
            }
            guard !decoded.isEmpty else { throw ImportError.missingDataParameter }
            return decoded
        }
        throw ImportError.missingDataParameter
    }

    /// Accepts both the standard and URL-safe alphabets, and tolerates the
    /// missing `=` padding some QR generators strip.
    static func decodeBase64(_ string: String) throws -> Data {
        var normalized = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        normalized.removeAll { $0 == "\n" || $0 == "\r" || $0 == " " }

        let remainder = normalized.count % 4
        if remainder > 0 {
            normalized.append(String(repeating: "=", count: 4 - remainder))
        }
        guard let data = Data(base64Encoded: normalized), !data.isEmpty else {
            throw ImportError.malformedDataParameter
        }
        return data
    }

    // MARK: - Protobuf

    static func decode(protobuf: Data) throws -> MigrationPayload {
        var reader = ProtoReader(protobuf)
        var accounts: [ImportedAccount] = []
        var skipped = 0
        var batchSize = 1
        var batchIndex = 0
        var batchID = 0

        while let field = try reader.nextField() {
            switch (field.number, field.wireType) {
            case (1, .lengthDelimited):
                var entry = try reader.readMessage()
                guard accounts.count + skipped < maximumAccountsPerPayload else {
                    throw ImportError.malformedPayload
                }
                if let account = try decodeOTPParameters(&entry) {
                    accounts.append(account)
                } else {
                    skipped += 1
                }
            // `Int(_:)` traps on overflow, and these come straight from a QR
            // anyone can show to the camera, so every conversion is checked.
            case (3, .varint):
                batchSize = try boundedInt(try reader.readVarint(), maximum: maximumBatchSize)
            case (4, .varint):
                batchIndex = try boundedInt(try reader.readVarint(), maximum: maximumBatchSize)
            case (5, .varint):
                // The id is only compared for equality; any 63-bit value is fine.
                batchID = try boundedInt(try reader.readVarint(), maximum: Int.max)
            default:
                // Field 2 is `version`, plus anything a future release adds.
                try reader.skip(field.wireType)
            }
        }

        guard !accounts.isEmpty || skipped > 0 else {
            throw ImportError.noAccountsInPayload
        }
        // A fragment claiming to be outside its own batch is not a real export.
        guard batchIndex < max(batchSize, 1) else { throw ImportError.malformedPayload }

        return MigrationPayload(
            accounts: accounts,
            batchSize: max(batchSize, 1),
            batchIndex: max(batchIndex, 0),
            batchID: batchID,
            skippedCount: skipped
        )
    }

    /// Returns `nil` for entries this version deliberately does not import
    /// (HOTP, MD5, or an empty secret) so the caller can count them.
    private static func decodeOTPParameters(
        _ reader: inout ProtoReader
    ) throws -> ImportedAccount? {
        var secret = Data()
        var name = ""
        var issuer = ""
        var algorithmValue: UInt64 = 0
        var digitsValue: UInt64 = 0
        var typeValue: UInt64 = 0

        while let field = try reader.nextField() {
            switch (field.number, field.wireType) {
            case (1, .lengthDelimited): secret = try reader.readLengthDelimited()
            case (2, .lengthDelimited): name = try reader.readString()
            case (3, .lengthDelimited): issuer = try reader.readString()
            case (4, .varint): algorithmValue = try reader.readVarint()
            case (5, .varint): digitsValue = try reader.readVarint()
            case (6, .varint): typeValue = try reader.readVarint()
            default:
                // Field 7 is the HOTP counter, which we never reach for TOTP.
                try reader.skip(field.wireType)
            }
        }

        // Type 0 is "unspecified"; Google's own decoder treats it as TOTP.
        guard typeValue == 0 || typeValue == 2 else { return nil }
        guard !secret.isEmpty, secret.count <= maximumSecretLength else { return nil }
        guard let algorithm = OTPAlgorithm(migrationValue: algorithmValue) else { return nil }

        return ImportedAccount(
            issuer: issuer,
            name: name.strippingIssuerPrefix(issuer),
            secret: secret,
            digits: digitCount(from: digitsValue),
            algorithm: algorithm,
            period: googleAuthenticatorPeriod
        )
    }

    private static func boundedInt(_ value: UInt64, maximum: Int) throws -> Int {
        guard value <= UInt64(maximum) else { throw ImportError.malformedPayload }
        return Int(value)
    }

    /// `digits` is a `DigitCount` enum, *not* the number of digits: 1 means six
    /// and 2 means eight. Reading it as a literal count is the single most
    /// common bug in third-party importers.
    private static func digitCount(from value: UInt64) -> Int {
        value == 2 ? 8 : 6
    }
}
