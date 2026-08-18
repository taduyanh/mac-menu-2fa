import Foundation

/// RFC 4648 base32, used only by `otpauth://` URLs.
///
/// The Google Authenticator migration payload carries raw secret bytes and must
/// *not* be run through this.
nonisolated enum Base32 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)

    /// Tolerant of the shapes secrets are pasted in: lowercase, missing padding,
    /// and the spaces or hyphens sites use to make them readable.
    static func decode(_ string: String) -> Data? {
        var accumulator: UInt32 = 0
        var bitsFilled = 0
        var output = Data()
        output.reserveCapacity(string.utf8.count * 5 / 8)

        for character in string.utf8 {
            switch character {
            case UInt8(ascii: " "), UInt8(ascii: "-"), UInt8(ascii: "\t"),
                 UInt8(ascii: "\n"), UInt8(ascii: "\r"):
                continue
            case UInt8(ascii: "="):
                continue // padding carries no bits; trailing partial group is dropped below
            default:
                break
            }

            guard let value = decodeValue(character) else { return nil }
            accumulator = (accumulator << 5) | UInt32(value)
            bitsFilled += 5

            if bitsFilled >= 8 {
                bitsFilled -= 8
                output.append(UInt8((accumulator >> UInt32(bitsFilled)) & 0xff))
            }
        }

        // Any leftover bits are the zero padding of the final group. If they are
        // non-zero the input was corrupted rather than merely unpadded.
        if bitsFilled > 0, accumulator & ((1 << UInt32(bitsFilled)) - 1) != 0 {
            return nil
        }
        return output.isEmpty ? nil : output
    }

    static func encode(_ data: Data) -> String {
        var accumulator: UInt32 = 0
        var bitsFilled = 0
        var output = [UInt8]()
        output.reserveCapacity((data.count * 8 + 4) / 5)

        for byte in data {
            accumulator = (accumulator << 8) | UInt32(byte)
            bitsFilled += 8
            while bitsFilled >= 5 {
                bitsFilled -= 5
                output.append(alphabet[Int((accumulator >> UInt32(bitsFilled)) & 0x1f)])
            }
        }
        if bitsFilled > 0 {
            output.append(alphabet[Int((accumulator << UInt32(5 - bitsFilled)) & 0x1f)])
        }
        while output.count % 8 != 0 {
            output.append(UInt8(ascii: "="))
        }
        return String(decoding: output, as: UTF8.self)
    }

    private static func decodeValue(_ character: UInt8) -> UInt8? {
        switch character {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"): character - UInt8(ascii: "A")
        case UInt8(ascii: "a")...UInt8(ascii: "z"): character - UInt8(ascii: "a")
        case UInt8(ascii: "2")...UInt8(ascii: "7"): character - UInt8(ascii: "2") + 26
        default: nil
        }
    }
}
