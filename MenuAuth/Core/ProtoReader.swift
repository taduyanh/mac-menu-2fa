import Foundation

/// A minimal protobuf wire-format reader.
///
/// The migration payload uses five fields of one message and seven of another;
/// linking SwiftProtobuf to read them would add a dependency and megabytes of
/// binary for what fits here. Only the wire format is implemented — no schema,
/// no reflection, no code generation.
nonisolated struct ProtoReader {
    enum WireType: UInt64 {
        case varint = 0
        case fixed64 = 1
        case lengthDelimited = 2
        case startGroup = 3
        case endGroup = 4
        case fixed32 = 5
    }

    enum Failure: Error, Equatable {
        case truncated
        case malformedVarint
        case unknownWireType(UInt64)
        case unsupportedGroup
        case fieldNumberOutOfRange
    }

    private let bytes: [UInt8]
    private var index: Int

    init(_ data: Data) {
        bytes = Array(data)
        index = 0
    }

    private init(bytes: [UInt8]) {
        self.bytes = bytes
        index = 0
    }

    var isAtEnd: Bool { index >= bytes.count }

    /// Reads the next tag. Returns `nil` at a clean end of message.
    mutating func nextField() throws -> (number: Int, wireType: WireType)? {
        guard !isAtEnd else { return nil }
        let tag = try readVarint()
        let rawWireType = tag & 0x07
        guard let wireType = WireType(rawValue: rawWireType) else {
            throw Failure.unknownWireType(rawWireType)
        }
        let number = Int(tag >> 3)
        guard number > 0 else { throw Failure.fieldNumberOutOfRange }
        return (number, wireType)
    }

    mutating func readVarint() throws -> UInt64 {
        var value: UInt64 = 0
        var shift: UInt64 = 0
        while true {
            guard index < bytes.count else { throw Failure.truncated }
            let byte = bytes[index]
            index += 1
            value |= UInt64(byte & 0x7f) << shift
            if byte & 0x80 == 0 { return value }
            shift += 7
            // A 64-bit varint is at most ten groups of seven bits.
            guard shift < 64 else { throw Failure.malformedVarint }
        }
    }

    mutating func readLengthDelimited() throws -> Data {
        let length = try readVarint()
        guard length <= UInt64(bytes.count - index) else { throw Failure.truncated }
        let start = index
        index += Int(length)
        return Data(bytes[start..<index])
    }

    mutating func readString() throws -> String {
        String(decoding: try readLengthDelimited(), as: UTF8.self)
    }

    /// A nested reader over a length-delimited field, for sub-messages.
    mutating func readMessage() throws -> ProtoReader {
        let length = try readVarint()
        guard length <= UInt64(bytes.count - index) else { throw Failure.truncated }
        let start = index
        index += Int(length)
        return ProtoReader(bytes: Array(bytes[start..<index]))
    }

    /// Advances past a field this decoder does not care about. Without this,
    /// a future Google Authenticator adding a field would break every import.
    mutating func skip(_ wireType: WireType) throws {
        switch wireType {
        case .varint:
            _ = try readVarint()
        case .fixed64:
            try advance(by: 8)
        case .lengthDelimited:
            let length = try readVarint()
            guard length <= UInt64(bytes.count - index) else { throw Failure.truncated }
            index += Int(length)
        case .fixed32:
            try advance(by: 4)
        case .startGroup, .endGroup:
            // Deprecated in proto2 and never emitted by the migration payload.
            throw Failure.unsupportedGroup
        }
    }

    private mutating func advance(by count: Int) throws {
        guard bytes.count - index >= count else { throw Failure.truncated }
        index += count
    }
}
