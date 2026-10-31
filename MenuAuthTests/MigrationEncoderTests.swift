import Foundation
import Testing

@testable import MenuAuth

@Suite("Migration export encoding")
struct MigrationEncoderTests {
    private func sample(_ count: Int) -> [ImportedAccount] {
        (0..<count).map { index in
            ImportedAccount(
                issuer: "Issuer\(index)",
                name: "user\(index)@example.com",
                secret: Data((0..<10).map { UInt8(($0 + index) & 0xff) }),
                digits: index % 2 == 0 ? 6 : 8,
                algorithm: [.sha1, .sha256, .sha512][index % 3]
            )
        }
    }

    @Test("Round-trips through the decoder")
    func roundTrips() throws {
        let accounts = sample(5)
        let urls = MigrationEncoder.urls(for: accounts)
        #expect(urls.count == 1)

        let payload = try MigrationDecoder.decode(urls[0])
        #expect(payload.accounts == accounts)
        #expect(payload.skippedCount == 0)
        #expect(payload.batchSize == 1)
    }

    @Test("Splits into batches that share an id and reassemble in order")
    func batches() throws {
        let accounts = sample(19)
        let urls = MigrationEncoder.urls(for: accounts, batchSize: 8, batchID: 42)
        #expect(urls.count == 3)

        let payloads = try urls.map { try MigrationDecoder.decode($0) }
        #expect(payloads.map(\.batchIndex) == [0, 1, 2])
        #expect(payloads.allSatisfy { $0.batchSize == 3 && $0.batchID == 42 })
        #expect(payloads.flatMap(\.accounts) == accounts)
    }

    @Test("Empty input yields no QR codes")
    func empty() {
        #expect(MigrationEncoder.urls(for: []).isEmpty)
    }

    @Test("A full batch fits in a QR code")
    func fullBatchRendersAsQR() {
        let url = MigrationEncoder.urls(for: sample(MigrationEncoder.defaultBatchSize))[0]
        #expect(QRCodeImage.make(from: url) != nil)
    }
}
