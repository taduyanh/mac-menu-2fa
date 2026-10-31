import Foundation

/// The inverse of `MigrationDecoder`: packs accounts into the
/// `otpauth-migration://offline?data=...` URLs Google Authenticator's
/// "Import accounts" scanner understands.
nonisolated enum MigrationEncoder {
    /// Google splits exports into QR codes of about this many accounts. Fewer
    /// per code keeps each QR sparse enough to scan from a screen.
    static let defaultBatchSize = 8

    /// One URL per batch, all sharing a batch id so the phone can tell they
    /// belong together.
    static func urls(
        for accounts: [ImportedAccount],
        batchSize: Int = defaultBatchSize,
        batchID: Int = Int.random(in: 1...Int(Int32.max))
    ) -> [String] {
        guard !accounts.isEmpty else { return [] }
        let size = max(batchSize, 1)
        let chunks = stride(from: 0, to: accounts.count, by: size).map {
            Array(accounts[$0..<min($0 + size, accounts.count)])
        }
        return chunks.enumerated().map { index, chunk in
            url(
                protobuf: encode(
                    chunk,
                    batchSize: chunks.count,
                    batchIndex: index,
                    batchID: batchID
                )
            )
        }
    }

    static func encode(
        _ accounts: [ImportedAccount],
        batchSize: Int,
        batchIndex: Int,
        batchID: Int
    ) -> Data {
        var out = Data()
        for account in accounts {
            var entry = Data()
            appendBytes(&entry, field: 1, account.secret)
            // The phone app stores `Issuer:name` in `name` and also fills
            // `issuer`; mirroring that keeps the account labelled correctly
            // there. The decoder strips the prefix again on the way back in.
            let name = account.issuer.isEmpty ? account.name : "\(account.issuer):\(account.name)"
            appendBytes(&entry, field: 2, Data(name.utf8))
            appendBytes(&entry, field: 3, Data(account.issuer.utf8))
            appendVarint(&entry, field: 4, algorithmValue(account.algorithm))
            // `DigitCount` enum: 1 is six digits, 2 is eight.
            appendVarint(&entry, field: 5, account.digits == 8 ? 2 : 1)
            appendVarint(&entry, field: 6, 2) // TOTP
            appendBytes(&out, field: 1, entry)
        }
        appendVarint(&out, field: 2, 1) // version
        appendVarint(&out, field: 3, UInt64(batchSize))
        appendVarint(&out, field: 4, UInt64(batchIndex))
        appendVarint(&out, field: 5, UInt64(batchID))
        return out
    }

    /// Percent-encodes the base64 the way Google Authenticator does, so `+`
    /// can't be misread as a space by a form-decoding parser.
    static func url(protobuf: Data) -> String {
        let escaped = protobuf.base64EncodedString()
            .replacingOccurrences(of: "+", with: "%2B")
            .replacingOccurrences(of: "/", with: "%2F")
            .replacingOccurrences(of: "=", with: "%3D")
        return "\(MigrationDecoder.scheme)://offline?data=\(escaped)"
    }

    private static func algorithmValue(_ algorithm: OTPAlgorithm) -> UInt64 {
        switch algorithm {
        case .sha1: 1
        case .sha256: 2
        case .sha512: 3
        }
    }

    // MARK: - Wire format

    private static func appendVarint(_ data: inout Data, field: Int, _ value: UInt64) {
        appendRawVarint(&data, UInt64(field) << 3)
        appendRawVarint(&data, value)
    }

    private static func appendBytes(_ data: inout Data, field: Int, _ payload: Data) {
        appendRawVarint(&data, UInt64(field) << 3 | 2)
        appendRawVarint(&data, UInt64(payload.count))
        data.append(payload)
    }

    private static func appendRawVarint(_ data: inout Data, _ value: UInt64) {
        var remaining = value
        repeat {
            var byte = UInt8(remaining & 0x7f)
            remaining >>= 7
            if remaining != 0 { byte |= 0x80 }
            data.append(byte)
        } while remaining != 0
    }
}
