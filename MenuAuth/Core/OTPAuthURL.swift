import Foundation

/// Parses a single-account `otpauth://totp/...` URL — the QR most sites show
/// when you enable 2FA.
///
/// MenuAuth's import flow is built around Google's bulk export, but a camera
/// pointed at a per-site QR should work rather than silently do nothing, and
/// the parsing is shared with the migration path.
nonisolated enum OTPAuthURL {
    static let scheme = "otpauth"

    static func canDecode(_ text: String) -> Bool {
        text.lowercased().hasPrefix(scheme + "://")
    }

    static func decode(_ text: String) throws -> ImportedAccount {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.utf8.count <= MigrationDecoder.maximumInputLength else {
            throw ImportError.unrecognizedQRCode
        }
        guard let components = URLComponents(string: trimmed),
              components.scheme?.lowercased() == scheme
        else {
            throw ImportError.unrecognizedQRCode
        }

        switch components.host?.lowercased() {
        case "totp", nil: break
        case "hotp": throw ImportError.unsupportedOTPType
        default: throw ImportError.unrecognizedQRCode
        }

        let queryItems = components.queryItems ?? []
        func value(_ name: String) -> String? {
            queryItems.first { $0.name.lowercased() == name }?
                .value?
                .trimmingCharacters(in: .whitespaces)
        }

        guard let rawSecret = value("secret"), !rawSecret.isEmpty else {
            throw ImportError.missingSecret
        }
        guard let secret = Base32.decode(rawSecret),
              secret.count <= MigrationDecoder.maximumSecretLength
        else {
            throw ImportError.invalidSecretEncoding
        }

        // The label is `path` minus its leading slash, and is conventionally
        // "Issuer:account". `URLComponents.path` is already percent-decoded.
        let label = String(components.path.dropFirst())
        let issuerFromQuery = value("issuer") ?? ""
        let issuerFromLabel = label.contains(":")
            ? String(label.prefix(while: { $0 != ":" })).trimmingCharacters(in: .whitespaces)
            : ""
        let issuer = issuerFromQuery.isEmpty ? issuerFromLabel : issuerFromQuery

        var name = label.strippingIssuerPrefix(issuer)
        if name.isEmpty { name = label }

        return ImportedAccount(
            issuer: issuer,
            name: name,
            secret: secret,
            digits: digits(from: value("digits")),
            algorithm: algorithm(from: value("algorithm")),
            period: period(from: value("period"))
        )
    }

    private static func digits(from raw: String?) -> Int {
        guard let raw, let parsed = Int(raw), (6...8).contains(parsed) else {
            return TOTP.defaultDigits
        }
        return parsed
    }

    private static func period(from raw: String?) -> Int {
        guard let raw, let parsed = Int(raw), parsed > 0, parsed <= 300 else {
            return TOTP.defaultPeriod
        }
        return parsed
    }

    private static func algorithm(from raw: String?) -> OTPAlgorithm {
        switch raw?.uppercased() {
        case "SHA256": .sha256
        case "SHA512": .sha512
        default: .sha1
        }
    }
}

/// What a decoded QR turned out to be. The scanner accepts either kind, so the
/// UI can react without re-sniffing the string.
nonisolated enum QRPayload: Sendable {
    case migration(MigrationPayload)
    case single(ImportedAccount)

    static func decode(_ text: String) throws -> QRPayload {
        if MigrationDecoder.canDecode(text) {
            return .migration(try MigrationDecoder.decode(text))
        }
        if OTPAuthURL.canDecode(text) {
            return .single(try OTPAuthURL.decode(text))
        }
        throw ImportError.unrecognizedQRCode
    }
}
