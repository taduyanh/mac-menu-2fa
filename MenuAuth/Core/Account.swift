import Foundation

/// The non-secret half of an account. This is what gets persisted to
/// `accounts.json` and what the panel renders while still locked, so the list
/// and countdown are visible without a biometric prompt.
nonisolated struct Account: Identifiable, Codable, Hashable, Sendable {
    let id: UUID
    var issuer: String
    var name: String
    var digits: Int
    var algorithm: OTPAlgorithm
    var period: Int
    var sortIndex: Int

    init(
        id: UUID = UUID(),
        issuer: String,
        name: String,
        digits: Int = TOTP.defaultDigits,
        algorithm: OTPAlgorithm = .sha1,
        period: Int = TOTP.defaultPeriod,
        sortIndex: Int = 0
    ) {
        self.id = id
        self.issuer = issuer
        self.name = name
        self.digits = digits
        self.algorithm = algorithm
        self.period = period
        self.sortIndex = sortIndex
    }

    /// What the row shows on its first line. Some issuers only populate `name`.
    var displayTitle: String {
        issuer.isEmpty ? name : issuer
    }

    /// What the row shows on its second line, empty when it would just repeat
    /// the title.
    var displaySubtitle: String {
        issuer.isEmpty ? "" : name
    }

    /// Identity for de-duplicating re-imports of the same export.
    var dedupeKey: String { Self.dedupeKey(issuer: issuer, name: name) }

    static func dedupeKey(issuer: String, name: String) -> String {
        "\(issuer.lowercased())\u{0}\(name.lowercased())"
    }

    func matches(searchText: String) -> Bool {
        guard !searchText.isEmpty else { return true }
        return issuer.localizedCaseInsensitiveContains(searchText)
            || name.localizedCaseInsensitiveContains(searchText)
    }
}

/// An account plus its secret, as produced by the QR decoders and consumed by
/// the store. Deliberately not `Codable` — this must never reach disk as-is.
nonisolated struct ImportedAccount: Sendable, Hashable {
    var issuer: String
    var name: String
    var secret: Data
    var digits: Int
    var algorithm: OTPAlgorithm
    var period: Int

    init(
        issuer: String,
        name: String,
        secret: Data,
        digits: Int = TOTP.defaultDigits,
        algorithm: OTPAlgorithm = .sha1,
        period: Int = TOTP.defaultPeriod
    ) {
        self.issuer = issuer
        self.name = name
        self.secret = secret
        self.digits = digits
        self.algorithm = algorithm
        self.period = period
    }

    var dedupeKey: String { Account.dedupeKey(issuer: issuer, name: name) }

    func account(id: UUID = UUID(), sortIndex: Int) -> Account {
        Account(
            id: id,
            issuer: issuer,
            name: name,
            digits: digits,
            algorithm: algorithm,
            period: period,
            sortIndex: sortIndex
        )
    }
}

nonisolated extension String {
    /// Google puts `"Issuer:account@example.com"` in `name` while also setting
    /// `issuer`. The mobile app strips the redundant prefix; so do we.
    func strippingIssuerPrefix(_ issuer: String) -> String {
        guard !issuer.isEmpty else { return self }
        let prefix = issuer + ":"
        guard lowercased().hasPrefix(prefix.lowercased()) else { return self }
        return String(dropFirst(prefix.count))
            .trimmingCharacters(in: .whitespaces)
    }
}
