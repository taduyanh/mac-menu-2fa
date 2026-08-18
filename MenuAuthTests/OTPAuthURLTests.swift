import Foundation
import Testing

@testable import MenuAuth

@Suite("otpauth:// single-account URLs")
struct OTPAuthURLTests {
    @Test("Parses the canonical example")
    func canonicalExample() throws {
        let account = try OTPAuthURL.decode(
            "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        )
        #expect(account.issuer == "Example")
        #expect(account.name == "alice@google.com")
        #expect(account.secret == Data("Hello!".utf8) + Data([0xde, 0xad, 0xbe, 0xef]))
        #expect(account.digits == 6)
        #expect(account.period == 30)
        #expect(account.algorithm == .sha1)
    }

    /// The migration payload and the otpauth URL for the same account must
    /// produce byte-identical secrets, or the two import paths disagree.
    @Test("Agrees with the migration decoder for the same account")
    func agreesWithMigrationDecoder() throws {
        let fromURL = try OTPAuthURL.decode(
            "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        )
        let fromMigration = try #require(
            try MigrationDecoder.decode(MigrationRealVectorTests.aliceURL).accounts.first
        )
        #expect(fromURL.secret == fromMigration.secret)
        #expect(fromURL.issuer == fromMigration.issuer)
        #expect(fromURL.name == fromMigration.name)
        #expect(fromURL.digits == fromMigration.digits)
        #expect(fromURL.algorithm == fromMigration.algorithm)
    }

    @Test("Explicit parameters override the defaults")
    func explicitParameters() throws {
        let account = try OTPAuthURL.decode(
            "otpauth://totp/ACME:bob?secret=JBSWY3DPEHPK3PXP&issuer=ACME"
                + "&algorithm=SHA512&digits=8&period=60"
        )
        #expect(account.algorithm == .sha512)
        #expect(account.digits == 8)
        #expect(account.period == 60)
    }

    @Test("Out-of-range parameters fall back to the defaults")
    func outOfRangeParametersFallBack() throws {
        let account = try OTPAuthURL.decode(
            "otpauth://totp/ACME:bob?secret=JBSWY3DPEHPK3PXP&digits=99&period=0&algorithm=WAT"
        )
        #expect(account.digits == 6)
        #expect(account.period == 30)
        #expect(account.algorithm == .sha1)
    }

    @Test("The issuer is taken from the label when the query omits it")
    func issuerFromLabel() throws {
        let account = try OTPAuthURL.decode(
            "otpauth://totp/GitHub:anhtd?secret=JBSWY3DPEHPK3PXP"
        )
        #expect(account.issuer == "GitHub")
        #expect(account.name == "anhtd")
    }

    @Test("The query issuer wins over the label")
    func queryIssuerWins() throws {
        let account = try OTPAuthURL.decode(
            "otpauth://totp/Old:anhtd?secret=JBSWY3DPEHPK3PXP&issuer=New"
        )
        #expect(account.issuer == "New")
        // The label prefix does not match the winning issuer, so it stays.
        #expect(account.name == "Old:anhtd")
    }

    @Test("Percent-encoded labels are decoded")
    func percentEncodedLabel() throws {
        let account = try OTPAuthURL.decode(
            "otpauth://totp/My%20Company:me%40example.com?secret=JBSWY3DPEHPK3PXP"
                + "&issuer=My%20Company"
        )
        #expect(account.issuer == "My Company")
        #expect(account.name == "me@example.com")
    }

    @Test("A lowercase, unpadded secret still decodes")
    func lowercaseSecret() throws {
        let account = try OTPAuthURL.decode(
            "otpauth://totp/ACME:bob?secret=jbswy3dpehpk3pxp"
        )
        #expect(account.secret == Data("Hello!".utf8) + Data([0xde, 0xad, 0xbe, 0xef]))
    }

    @Test("Counter-based accounts are refused with a specific message")
    func hotpIsRefused() {
        #expect(throws: ImportError.unsupportedOTPType) {
            try OTPAuthURL.decode("otpauth://hotp/ACME:bob?secret=JBSWY3DPEHPK3PXP&counter=1")
        }
    }

    @Test("A missing secret is refused")
    func missingSecret() {
        #expect(throws: ImportError.missingSecret) {
            try OTPAuthURL.decode("otpauth://totp/ACME:bob?issuer=ACME")
        }
    }

    @Test("A non-base32 secret is refused")
    func invalidSecret() {
        #expect(throws: ImportError.invalidSecretEncoding) {
            try OTPAuthURL.decode("otpauth://totp/ACME:bob?secret=not-base32-1889")
        }
    }
}

@Suite("QR payload dispatch")
struct QRPayloadTests {
    @Test("A migration QR is recognised as a migration payload")
    func recognisesMigration() throws {
        let payload = try QRPayload.decode(MigrationRealVectorTests.aliceURL)
        guard case .migration(let migration) = payload else {
            Issue.record("expected a migration payload")
            return
        }
        #expect(migration.accounts.count == 1)
    }

    @Test("A per-site QR is recognised as a single account")
    func recognisesSingle() throws {
        let payload = try QRPayload.decode(
            "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        )
        guard case .single(let account) = payload else {
            Issue.record("expected a single account")
            return
        }
        #expect(account.name == "alice@google.com")
    }

    /// Pointing the camera at a Wi-Fi or URL QR should say so, not fail mutely.
    @Test(
        "Unrelated QR codes get an actionable error",
        arguments: [
            "https://example.com",
            "WIFI:S:MyNetwork;T:WPA;P:secret;;",
            "hello world",
        ]
    )
    func rejectsUnrelatedQRCodes(text: String) {
        #expect(throws: ImportError.unrecognizedQRCode) {
            try QRPayload.decode(text)
        }
    }
}
