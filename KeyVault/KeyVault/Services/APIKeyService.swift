import Foundation
import Security

private struct APIKeyMeta: Codable {
    var name: String
    var service: String?
    var notes: String?
    var createdDate: Date?
}

struct APIKeyService {
    private static let keychainService = "io.github.sevmorris.KeyVault"
    private static let metaDefaultsKey = "APIKeyMeta"

    static func save(key: EncryptionKey, secret: String) throws {
        guard let secretData = secret.data(using: .utf8) else {
            throw KeyError.keychainError(errSecParam)
        }
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: key.id.uuidString,
            kSecValueData: secretData
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeyError.keychainError(status)
        }
        saveMeta(key: key)
    }

    static func loadSecret(for id: UUID) throws -> String {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: id.uuidString,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data,
              let secret = String(data: data, encoding: .utf8) else {
            throw KeyError.keychainError(status)
        }
        return secret
    }

    static func loadAll() -> [EncryptionKey] {
        let metaDict = loadMetaDict()
        return metaDict.compactMap { (uuidString, meta) -> EncryptionKey? in
            guard let id = UUID(uuidString: uuidString) else { return nil }
            return EncryptionKey(
                id: id,
                type: .api,
                name: meta.name,
                service: meta.service,
                notes: meta.notes,
                createdDate: meta.createdDate,
                hasPrivateKey: false
            )
        }.sorted { $0.name < $1.name }
    }

    static func delete(id: UUID) throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: id.uuidString
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeyError.keychainError(status)
        }
        var meta = loadMetaDict()
        meta.removeValue(forKey: id.uuidString)
        saveMetaDict(meta)
    }

    static func update(key: EncryptionKey, newSecret: String?) throws {
        if let secret = newSecret, let secretData = secret.data(using: .utf8) {
            let query: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: keychainService,
                kSecAttrAccount: key.id.uuidString
            ]
            let attributes: [CFString: Any] = [kSecValueData: secretData]
            let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            guard status == errSecSuccess else {
                throw KeyError.keychainError(status)
            }
        }
        saveMeta(key: key)
    }

    private static func saveMeta(key: EncryptionKey) {
        var meta = loadMetaDict()
        meta[key.id.uuidString] = APIKeyMeta(
            name: key.name,
            service: key.service,
            notes: key.notes,
            createdDate: key.createdDate
        )
        saveMetaDict(meta)
    }

    private static func loadMetaDict() -> [String: APIKeyMeta] {
        guard let data = UserDefaults.standard.data(forKey: metaDefaultsKey),
              let dict = try? JSONDecoder().decode([String: APIKeyMeta].self, from: data) else {
            return [:]
        }
        return dict
    }

    private static func saveMetaDict(_ dict: [String: APIKeyMeta]) {
        guard let data = try? JSONEncoder().encode(dict) else { return }
        UserDefaults.standard.set(data, forKey: metaDefaultsKey)
    }
}
