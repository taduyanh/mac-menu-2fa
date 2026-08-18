import Foundation

/// A tiny protobuf *writer*, used only by tests to build fixtures.
///
/// Fixtures are hand-built rather than copied from a real export so that no
/// live secret ever lands in the repository. The two real-world payloads in
/// `MigrationDecoderTests` guard against this writer and the reader sharing a
/// misunderstanding of the wire format.
struct ProtoWriter {
    private(set) var data = Data()

    mutating func varint(field: Int, _ value: UInt64) {
        appendTag(field: field, wireType: 0)
        appendVarint(value)
    }

    mutating func bytes(field: Int, _ payload: Data) {
        appendTag(field: field, wireType: 2)
        appendVarint(UInt64(payload.count))
        data.append(payload)
    }

    mutating func string(field: Int, _ value: String) {
        bytes(field: field, Data(value.utf8))
    }

    mutating func message(field: Int, _ builder: (inout ProtoWriter) -> Void) {
        var nested = ProtoWriter()
        builder(&nested)
        bytes(field: field, nested.data)
    }

    /// Only used to prove unknown fields are skipped rather than fatal.
    mutating func fixed32(field: Int, _ value: UInt32) {
        appendTag(field: field, wireType: 5)
        withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) }
    }

    mutating func fixed64(field: Int, _ value: UInt64) {
        appendTag(field: field, wireType: 1)
        withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) }
    }

    private mutating func appendTag(field: Int, wireType: UInt64) {
        appendVarint(UInt64(field) << 3 | wireType)
    }

    private mutating func appendVarint(_ value: UInt64) {
        var remaining = value
        repeat {
            var byte = UInt8(remaining & 0x7f)
            remaining >>= 7
            if remaining != 0 { byte |= 0x80 }
            data.append(byte)
        } while remaining != 0
    }
}

extension ProtoWriter {
    /// Builds a `MigrationPayload` containing the given entries.
    static func migrationPayload(
        entries: [(secret: Data, name: String, issuer: String, algorithm: UInt64?, digits: UInt64?, type: UInt64?)],
        version: UInt64? = 1,
        batchSize: UInt64? = nil,
        batchIndex: UInt64? = nil,
        batchID: UInt64? = nil
    ) -> Data {
        var writer = ProtoWriter()
        for entry in entries {
            writer.message(field: 1) { parameters in
                parameters.bytes(field: 1, entry.secret)
                parameters.string(field: 2, entry.name)
                parameters.string(field: 3, entry.issuer)
                if let algorithm = entry.algorithm { parameters.varint(field: 4, algorithm) }
                if let digits = entry.digits { parameters.varint(field: 5, digits) }
                if let type = entry.type { parameters.varint(field: 6, type) }
            }
        }
        if let version { writer.varint(field: 2, version) }
        if let batchSize { writer.varint(field: 3, batchSize) }
        if let batchIndex { writer.varint(field: 4, batchIndex) }
        if let batchID { writer.varint(field: 5, batchID) }
        return writer.data
    }

    /// Wraps protobuf bytes in the URL form a QR code actually carries,
    /// percent-encoding the base64 the way Google Authenticator does.
    static func migrationURL(_ payload: Data) -> String {
        let base64 = payload.base64EncodedString()
        let escaped = base64
            .replacingOccurrences(of: "+", with: "%2B")
            .replacingOccurrences(of: "/", with: "%2F")
            .replacingOccurrences(of: "=", with: "%3D")
        return "otpauth-migration://offline?data=\(escaped)"
    }
}
