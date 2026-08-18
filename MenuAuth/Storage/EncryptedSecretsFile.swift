import CryptoKit
import Foundation

/// All TOTP secrets, encrypted into a single file with one AES-GCM key.
///
/// This exists to solve a very concrete problem. Storing one Keychain item per
/// account means one *access control list* per account, and macOS prompts for
/// the login password once per ACL — so twenty accounts meant twenty prompts,
/// and "Always Allow" only ever authorised the single item it was shown for.
///
/// Now the Keychain holds exactly one thing: the key to this file. One item,
/// one ACL, one prompt. The secrets themselves live here, encrypted, and the
/// file is worthless without the key.
nonisolated struct EncryptedSecretsFile: Sendable {
    enum Failure: Error, LocalizedError {
        case decryptionFailed
        case corrupted

        var errorDescription: String? {
            switch self {
            case .decryptionFailed:
                "MenuAuth couldn't decrypt its stored secrets. If you removed its key "
                    + "from the Keychain, you'll need to import your accounts again."
            case .corrupted:
                "MenuAuth's secret store is damaged and couldn't be read."
            }
        }
    }

    let fileURL: URL

    var exists: Bool {
        FileManager.default.fileExists(atPath: fileURL.path)
    }

    /// Returns an empty dictionary when the file does not exist yet, so a first
    /// run is not an error.
    func load(key: SymmetricKey) throws -> [UUID: Data] {
        guard exists else { return [:] }
        let data = try Data(contentsOf: fileURL)
        guard !data.isEmpty else { return [:] }

        let plaintext: Data
        do {
            let box = try AES.GCM.SealedBox(combined: data)
            plaintext = try AES.GCM.open(box, using: key)
        } catch {
            // GCM authenticates as well as decrypts, so this covers both a
            // wrong key and a tampered file.
            throw Failure.decryptionFailed
        }

        guard let raw = try? JSONDecoder().decode([String: Data].self, from: plaintext) else {
            throw Failure.corrupted
        }
        return Dictionary(
            uniqueKeysWithValues: raw.compactMap { identifier, secret in
                UUID(uuidString: identifier).map { ($0, secret) }
            }
        )
    }

    func save(_ secrets: [UUID: Data], key: SymmetricKey) throws {
        let raw = Dictionary(
            uniqueKeysWithValues: secrets.map { ($0.key.uuidString, $0.value) }
        )
        let plaintext = try JSONEncoder().encode(raw)
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else { throw Failure.corrupted }

        // Atomic so a crash mid-write cannot truncate the store.
        try combined.write(to: fileURL, options: [.atomic])
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: fileURL.path
        )
    }

    func delete() throws {
        guard exists else { return }
        try FileManager.default.removeItem(at: fileURL)
    }
}
