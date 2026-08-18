import Foundation
import Testing

@testable import MenuAuth

@Suite("Real-world export payloads")
struct MigrationRealVectorTests {
    /// The canonical public example. Its secret is the well-known
    /// `Hello!\u{de}\u{ad}\u{be}\u{ef}` test value, not anyone's real account.
    ///
    /// Documented to decode to:
    /// `otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example`
    static let aliceURL = "otpauth-migration://offline?data="
        + "CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZTAC"

    /// A second public example. Its `OtpParameters` has **no** `type` field,
    /// which is how real exports often look — a decoder that required
    /// `type == 2` would reject genuine data.
    static let githubURL = "otpauth-migration://offline?data="
        + "CiQKChkAMJCF7zetb50SEmdpdGh1Yi5jb206YnJvb2tzdBoCbWUQARgBKAE%3D"

    @Test("Decodes the published Example/alice vector")
    func decodesAliceVector() throws {
        let payload = try MigrationDecoder.decode(Self.aliceURL)

        #expect(payload.accounts.count == 1)
        #expect(payload.skippedCount == 0)

        let account = try #require(payload.accounts.first)
        #expect(account.issuer == "Example")
        // The redundant "Example:" prefix is stripped, as the phone app does.
        #expect(account.name == "alice@google.com")
        #expect(account.secret == Data("Hello!".utf8) + Data([0xde, 0xad, 0xbe, 0xef]))
        #expect(account.digits == 6)
        #expect(account.algorithm == .sha1)
        #expect(account.period == 30)
    }

    /// Cross-checks the decoder against `Base32`: the published otpauth URL for
    /// this vector states the secret is `JBSWY3DPEHPK3PXP`, so re-encoding the
    /// decoded bytes must reproduce it.
    @Test("Decoded secret re-encodes to the documented base32")
    func secretMatchesDocumentedBase32() throws {
        let payload = try MigrationDecoder.decode(Self.aliceURL)
        let account = try #require(payload.accounts.first)
        #expect(Base32.encode(account.secret) == "JBSWY3DPEHPK3PXP")
    }

    @Test("Decodes a payload whose entry omits the type field")
    func decodesEntryWithoutTypeField() throws {
        let payload = try MigrationDecoder.decode(Self.githubURL)

        #expect(payload.accounts.count == 1)
        #expect(payload.skippedCount == 0)
        #expect(payload.batchSize == 1)
        #expect(payload.batchID == 1)

        let account = try #require(payload.accounts.first)
        #expect(account.issuer == "me")
        #expect(account.name == "github.com:brookst")
        #expect(account.secret == Data([0x19, 0x00, 0x30, 0x90, 0x85, 0xef, 0x37, 0xad, 0x6f, 0x9d]))
    }

    /// A secret containing a NUL byte must survive; treating the payload as a
    /// C string would truncate this one at its second byte.
    @Test("A secret containing a zero byte survives intact")
    func secretWithNulByteSurvives() throws {
        let payload = try MigrationDecoder.decode(Self.githubURL)
        let account = try #require(payload.accounts.first)
        #expect(account.secret.count == 10)
        #expect(account.secret[1] == 0x00)
    }

    /// The generated code is what the user ultimately compares against their
    /// phone, so pin it for a fixed instant.
    @Test("Produces a stable code for a fixed time")
    func generatesExpectedCode() throws {
        let payload = try MigrationDecoder.decode(Self.aliceURL)
        let account = try #require(payload.accounts.first)

        // JBSWY3DPEHPK3PXP at t=0 is the widely reproduced value 282760.
        let code = TOTP.code(
            secret: account.secret,
            counter: 0,
            digits: account.digits,
            algorithm: account.algorithm
        )
        #expect(code == "282760")
    }
}

@Suite("Migration payload parsing")
struct MigrationDecoderTests {
    private func url(
        _ entries: [(secret: Data, name: String, issuer: String, algorithm: UInt64?, digits: UInt64?, type: UInt64?)],
        batchSize: UInt64? = nil,
        batchIndex: UInt64? = nil,
        batchID: UInt64? = nil
    ) -> String {
        ProtoWriter.migrationURL(
            ProtoWriter.migrationPayload(
                entries: entries,
                batchSize: batchSize,
                batchIndex: batchIndex,
                batchID: batchID
            )
        )
    }

    /// `digits` is a `DigitCount` enum, not a literal count. Reading it as a
    /// number is the most common third-party importer bug: it yields 1 or 2
    /// digit codes that never match the phone.
    @Test("digits is an enum: 1 means six, 2 means eight")
    func digitsEnumMapping() throws {
        let payload = try MigrationDecoder.decode(
            url([
                (Data("aaaaaaaaaa".utf8), "six", "Issuer", nil, 1, 2),
                (Data("bbbbbbbbbb".utf8), "eight", "Issuer", nil, 2, 2),
                (Data("cccccccccc".utf8), "unspecified", "Issuer", nil, 0, 2),
            ])
        )
        #expect(payload.accounts.map(\.digits) == [6, 8, 6])
    }

    @Test("Algorithm enum maps to the hash actually used")
    func algorithmMapping() throws {
        let payload = try MigrationDecoder.decode(
            url([
                (Data("aaaaaaaaaa".utf8), "a", "I", 0, nil, 2),
                (Data("bbbbbbbbbb".utf8), "b", "I", 1, nil, 2),
                (Data("cccccccccc".utf8), "c", "I", 2, nil, 2),
                (Data("dddddddddd".utf8), "d", "I", 3, nil, 2),
            ])
        )
        #expect(payload.accounts.map(\.algorithm) == [.sha1, .sha1, .sha256, .sha512])
    }

    /// HOTP, MD5 and empty secrets are counted rather than dropped in silence,
    /// so the import sheet can tell the user something was left behind.
    @Test("Unsupported entries are counted, not silently dropped")
    func unsupportedEntriesAreCounted() throws {
        let payload = try MigrationDecoder.decode(
            url([
                (Data("aaaaaaaaaa".utf8), "good", "I", 1, 1, 2),
                (Data("bbbbbbbbbb".utf8), "hotp", "I", 1, 1, 1),
                (Data("cccccccccc".utf8), "md5", "I", 4, 1, 2),
                (Data(), "empty", "I", 1, 1, 2),
            ])
        )
        #expect(payload.accounts.count == 1)
        #expect(payload.accounts.first?.name == "good")
        #expect(payload.skippedCount == 3)
    }

    @Test("Batch fields are read for multi-QR exports")
    func batchFields() throws {
        let payload = try MigrationDecoder.decode(
            url(
                [(Data("aaaaaaaaaa".utf8), "a", "I", 1, 1, 2)],
                batchSize: 3,
                batchIndex: 1,
                batchID: 42
            )
        )
        #expect(payload.batchSize == 3)
        #expect(payload.batchIndex == 1)
        #expect(payload.batchID == 42)
        #expect(!payload.isSingleFragment)
    }

    @Test("A payload without batch fields is a single fragment")
    func missingBatchFieldsDefaultToSingle() throws {
        let payload = try MigrationDecoder.decode(
            url([(Data("aaaaaaaaaa".utf8), "a", "I", 1, 1, 2)])
        )
        #expect(payload.batchSize == 1)
        #expect(payload.isSingleFragment)
    }

    /// If Google adds a field, existing installs must keep working.
    @Test("Unknown fields are skipped rather than fatal")
    func unknownFieldsAreSkipped() throws {
        var writer = ProtoWriter()
        writer.message(field: 1) { parameters in
            parameters.bytes(field: 1, Data("aaaaaaaaaa".utf8))
            parameters.string(field: 2, "account")
            parameters.string(field: 3, "Issuer")
            parameters.varint(field: 6, 2)
            parameters.fixed32(field: 19, 0xdead_beef) // unknown, inside the entry
            parameters.string(field: 20, "future")
        }
        writer.varint(field: 2, 1)
        writer.fixed64(field: 15, 1) // unknown, at the top level
        writer.string(field: 16, "also future")

        let payload = try MigrationDecoder.decode(ProtoWriter.migrationURL(writer.data))
        #expect(payload.accounts.count == 1)
        #expect(payload.accounts.first?.name == "account")
    }

    @Test("The issuer prefix is stripped from the label only when it matches")
    func issuerPrefixStripping() throws {
        let payload = try MigrationDecoder.decode(
            url([
                (Data("aaaaaaaaaa".utf8), "GitHub:anhtd", "GitHub", 1, 1, 2),
                (Data("bbbbbbbbbb".utf8), "Google:me@example.com", "Google", 1, 1, 2),
                (Data("cccccccccc".utf8), "AWS:root", "Amazon", 1, 1, 2),
                (Data("dddddddddd".utf8), "plain@example.com", "Fastmail", 1, 1, 2),
            ])
        )
        #expect(payload.accounts.map(\.name) == [
            "anhtd",
            "me@example.com",
            "AWS:root",          // prefix does not match the issuer, so kept
            "plain@example.com", // no prefix at all
        ])
    }

    @Test("An entry with no issuer keeps its bare label")
    func missingIssuer() throws {
        let payload = try MigrationDecoder.decode(
            url([(Data("aaaaaaaaaa".utf8), "solo@example.com", "", 1, 1, 2)])
        )
        let account = try #require(payload.accounts.first)
        #expect(account.issuer == "")
        #expect(account.name == "solo@example.com")

        // With no issuer the row falls back to showing the bare label.
        let stored = account.account(sortIndex: 0)
        #expect(stored.displayTitle == "solo@example.com")
        #expect(stored.displaySubtitle == "")
    }
}

@Suite("Migration URL handling")
struct MigrationURLTests {
    /// Byte 3 of this secret lands on a base64 group boundary such that the
    /// encoding contains a literal `+`. The `#require` below keeps that
    /// property honest if the fixture ever changes.
    static let plusProducingSecret = Data([0x01, 0x02, 0xfb, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a])

    /// `+` is a real base64 character. A query parser that form-decodes turns
    /// it into a space, which still base64-decodes but yields wrong secrets —
    /// silent corruption rather than a visible error.
    @Test("A percent-encoded plus survives extraction")
    func plusIsNotTurnedIntoSpace() throws {
        let payload = ProtoWriter.migrationPayload(
            entries: [(Self.plusProducingSecret, "plus", "Issuer", 1, 1, 2)]
        )
        try #require(
            payload.base64EncodedString().contains("+"),
            "fixture must exercise the '+' path"
        )

        let decoded = try MigrationDecoder.decode(ProtoWriter.migrationURL(payload))
        #expect(decoded.accounts.first?.secret == Self.plusProducingSecret)
    }

    /// Guards the specific corruption: form-decoding would yield a space here.
    @Test("Extraction yields a plus, never a space")
    func extractionPreservesPlusLiterally() throws {
        let extracted = try MigrationDecoder.extractDataParameter(
            from: "otpauth-migration://offline?data=CiAKCgEC%2BwQFBgcICQoSBHBsdXM%3D"
        )
        #expect(extracted.contains("+"))
        #expect(!extracted.contains(" "))
        #expect(extracted == "CiAKCgEC+wQFBgcICQoSBHBsdXM=")
    }

    @Test("Both base64 alphabets decode")
    func acceptsBothAlphabets() throws {
        let payload = ProtoWriter.migrationPayload(
            entries: [(Self.plusProducingSecret, "a", "I", 1, 1, 2)]
        )
        let standard = payload.base64EncodedString()
        try #require(standard.contains("+"), "fixture must differ between alphabets")
        let urlSafe = standard
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        let fromStandard = try MigrationDecoder.decodeBase64(standard)
        let fromURLSafe = try MigrationDecoder.decodeBase64(urlSafe)
        #expect(fromStandard == fromURLSafe)
    }

    @Test("Missing padding is tolerated")
    func toleratesMissingPadding() throws {
        let payload = ProtoWriter.migrationPayload(
            entries: [(Data("aaaaaaaaaa".utf8), "a", "I", 1, 1, 2)]
        )
        let unpadded = payload.base64EncodedString().replacingOccurrences(of: "=", with: "")
        #expect(try MigrationDecoder.decodeBase64(unpadded) == payload)
    }

    @Test("The data parameter is found regardless of position")
    func findsDataAmongOtherParameters() throws {
        let payload = ProtoWriter.migrationPayload(
            entries: [(Data("aaaaaaaaaa".utf8), "a", "I", 1, 1, 2)]
        )
        let base64 = payload.base64EncodedString()
            .replacingOccurrences(of: "+", with: "%2B")
            .replacingOccurrences(of: "/", with: "%2F")
            .replacingOccurrences(of: "=", with: "%3D")
        let url = "otpauth-migration://offline?foo=bar&data=\(base64)&baz=qux"
        #expect(try MigrationDecoder.decode(url).accounts.count == 1)
    }

    @Test(
        "Non-migration input is rejected with a usable message",
        arguments: [
            "https://example.com",
            "otpauth-migration://offline",
            "otpauth-migration://offline?other=1",
            "",
            "   ",
        ]
    )
    func rejectsNonMigrationInput(text: String) {
        #expect(throws: ImportError.self) {
            try MigrationDecoder.decode(text)
        }
    }

    @Test("Truncated protobuf is reported rather than half-imported")
    func rejectsTruncatedPayload() {
        let payload = ProtoWriter.migrationPayload(
            entries: [(Data("aaaaaaaaaa".utf8), "account", "Issuer", 1, 1, 2)]
        )
        let truncated = payload.prefix(payload.count - 5)
        #expect(throws: (any Error).self) {
            try MigrationDecoder.decode(protobuf: Data(truncated))
        }
    }

    @Test("Garbage that happens to be valid base64 is rejected")
    func rejectsGarbagePayload() {
        let garbage = Data([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
        #expect(throws: (any Error).self) {
            try MigrationDecoder.decode(
                "otpauth-migration://offline?data=" + garbage.base64EncodedString()
            )
        }
    }
}
