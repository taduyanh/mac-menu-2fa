import Foundation
import Testing

@testable import MenuAuth

@Suite("RFC 4648 base32")
struct Base32Tests {
    @Test(
        "Decode reference vectors",
        arguments: [
            ("MY======", "f"),
            ("MZXQ====", "fo"),
            ("MZXW6===", "foo"),
            ("MZXW6YQ=", "foob"),
            ("MZXW6YTB", "fooba"),
            ("MZXW6YTBOI======", "foobar"),
        ]
    )
    func decodeVectors(encoded: String, plain: String) {
        #expect(Base32.decode(encoded) == Data(plain.utf8))
    }

    @Test(
        "Encode reference vectors",
        arguments: [
            ("f", "MY======"),
            ("fo", "MZXQ===="),
            ("foo", "MZXW6==="),
            ("foob", "MZXW6YQ="),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI======"),
        ]
    )
    func encodeVectors(plain: String, encoded: String) {
        #expect(Base32.encode(Data(plain.utf8)) == encoded)
    }

    /// Sites present secrets lowercase, space-grouped, and unpadded. All three
    /// must decode to the same bytes or users get "invalid code" on paste.
    @Test("Decoding tolerates the shapes secrets are presented in")
    func decodeIsTolerant() {
        let canonical = Base32.decode("MZXW6YTBOI======")
        #expect(Base32.decode("mzxw6ytboi") == canonical)
        #expect(Base32.decode("MZXW 6YTB OI") == canonical)
        #expect(Base32.decode("MZXW-6YTB-OI") == canonical)
        #expect(Base32.decode("MZXW6YTBOI") == canonical)
    }

    @Test("The RFC 6238 seed round-trips")
    func rfcSeedRoundTrips() {
        let secret = Data("12345678901234567890".utf8)
        let encoded = Base32.encode(secret)
        #expect(encoded == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        #expect(Base32.decode(encoded) == secret)
    }

    @Test("Characters outside the alphabet are rejected")
    func rejectsInvalidCharacters() {
        #expect(Base32.decode("MZXW6YTB1") == nil) // 1 is not in the alphabet
        #expect(Base32.decode("MZXW6YTB8") == nil) // nor is 8
        #expect(Base32.decode("MZXW6YTB!") == nil)
    }

    /// An empty secret would silently produce valid-looking codes, so it is
    /// treated as a decode failure rather than as empty data.
    @Test("Empty input is a failure, not empty data")
    func emptyIsFailure() {
        #expect(Base32.decode("") == nil)
        #expect(Base32.decode("========") == nil)
    }

    @Test("Non-zero padding bits are rejected as corruption")
    func rejectsNonZeroPaddingBits() {
        // "MB" -> 5 bits of 'M' + 5 of 'B' = 10 bits: 1 byte plus 2 leftover
        // bits. 'B' (1) leaves those bits set, so this is not a valid encoding.
        #expect(Base32.decode("MB") == nil)
        #expect(Base32.decode("MY") != nil) // 'Y' (24) leaves the low bits zero
    }
}
