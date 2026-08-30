import Foundation
import LocalAuthentication
import Security

/// Keychain-backed store for the secrets KeyVault *owns* — API keys and notes —
/// as opposed to the SSH/GPG/Age types, which are managers over key material
/// that already exists on disk and has its own backup story.
///
/// Every item is self-describing. The previous design kept names and services
/// in UserDefaults and only the payload in the Keychain, which made the plist
/// the index: losing it (container reset, corruption, a bad migration) left the
/// secrets intact but anonymous — blobs keyed by a UUID nothing referenced any
/// more. Recoverable when the contents are re-issuable tokens; not recoverable
/// when they are the things you cannot ask anyone to send again.
///
/// So the Keychain item now carries its own metadata:
///   • kSecAttrLabel       — display name
///   • kSecAttrDescription — KeyType raw value
///   • kSecAttrComment     — JSON of the remaining fields
///
/// `loadAll` enumerates the Keychain and reads those attributes. UserDefaults
/// is kept only to migrate items written by the old scheme.
enum SecretStore {
    static let keychainService = "io.github.sevmorris.KeyVault"

    // MARK: - Keychain protection
    //
    // Items used to be stored with kSecAttrAccessible and no access control,
    // which meant any process running as the user could read every note and
    // API key with no prompt at all:
    //
    //   security find-generic-password -s io.github.sevmorris.KeyVault -w
    //
    // returned a stored secret directly. The reveal button in KeyDetailView
    // guards against someone reading the screen; it never guarded against
    // software.
    //
    // The fix is a SecAccessControl requiring user presence — Touch ID, watch,
    // or the login password — on every read of the payload.
    //
    // Note on what was NOT done. The obvious move is the data-protection
    // keychain, which is what makes a notarytool profile unreadable by the
    // `security` CLI. It is not reachable here: it needs an application
    // identifier from a provisioning profile, and this app is built ad-hoc and
    // signed Developer ID with no profile. Measured, not assumed —
    //
    //   ad-hoc, kSecUseDataProtectionKeychain          -> -34018 missing entitlement
    //   Developer ID, no entitlement                   -> -34018
    //   Developer ID + keychain-access-groups, no profile -> killed on launch
    //
    // whereas a SecAccessControl on this keychain works with no entitlement at
    // all, and does block the CLI: the same `security` read that returns a
    // secret instantly for an unprotected item blocks awaiting authentication
    // for a protected one.

    /// Reused so that reveal-then-copy does not authenticate twice. Short on
    /// purpose: this is the window in which someone at an already-unlocked Mac
    /// can read a second secret without touching the sensor again.
    private static let authContext: LAContext = {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 30
        return context
    }()

    private static func accessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        // ThisDeviceOnly: the secret must not ride an iCloud backup to another
        // machine. Moving a vault between Macs goes through
        // VaultExportService, which is the path that has actually been drilled.
        guard let control = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            &error
        ) else {
            throw KeyError.keychainError(errSecParam)
        }
        return control
    }
    private static let legacyMetaDefaultsKey = "APIKeyMeta"
    private static let migrationDoneKey = "SecretStoreMetadataMigrated"

    /// The fields that don't have a dedicated Keychain attribute.
    private struct StoredMeta: Codable {
        var service: String?
        var notes: String?
        var createdDate: Date?
    }

    /// Types this store owns. SSH/GPG/Age are handled by their own services.
    static let ownedTypes: Set<KeyType> = [.api, .note]

    // MARK: - Write

    static func save(_ key: EncryptionKey, secret: String) throws {
        guard let secretData = secret.data(using: .utf8) else {
            throw KeyError.keychainError(errSecParam)
        }

        var query = baseQuery(id: key.id)
        query[kSecValueData] = secretData
        // kSecAttrAccessControl replaces kSecAttrAccessible — setting both is
        // an error, and the access control carries the accessibility itself.
        query[kSecAttrAccessControl] = try accessControl()
        attributes(for: key).forEach { query[$0.key] = $0.value }

        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
            // Adding over an existing account silently failed before; an update
            // is what the caller meant, and losing the write is not acceptable
            // for a store of things that cannot be re-created.
            try update(key, newSecret: secret)
            return
        }
        guard status == errSecSuccess else { throw KeyError.keychainError(status) }
    }

    static func update(_ key: EncryptionKey, newSecret: String?) throws {
        var changes = attributes(for: key)
        if let newSecret {
            guard let data = newSecret.data(using: .utf8) else {
                throw KeyError.keychainError(errSecParam)
            }
            changes[kSecValueData] = data
        }
        // Editing an item written before access control existed upgrades it in
        // place, so the vault protects itself as you touch it rather than
        // waiting on a migration to sweep everything.
        changes[kSecAttrAccessControl] = try accessControl()

        let status = SecItemUpdate(baseQuery(id: key.id) as CFDictionary,
                                   changes as CFDictionary)
        guard status == errSecSuccess else { throw KeyError.keychainError(status) }
    }

    static func delete(id: UUID) throws {
        let status = SecItemDelete(baseQuery(id: id) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeyError.keychainError(status)
        }
        var legacy = loadLegacyMetaDict()
        if legacy.removeValue(forKey: id.uuidString) != nil {
            saveLegacyMetaDict(legacy)
        }
    }

    // MARK: - Read

    /// Reading the payload is what triggers authentication — `loadAll` reads
    /// attributes only and stays silent, so browsing the list never prompts and
    /// revealing a secret does.
    static func loadSecret(for id: UUID) throws -> String {
        var query = baseQuery(id: id)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext] = authContext

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess,
              let data = result as? Data,
              let secret = String(data: data, encoding: .utf8) else {
            throw KeyError.keychainError(status)
        }
        return secret
    }

    /// Everything this store owns, read from the Keychain itself.
    /// Pass a type to filter; nil returns all owned types.
    static func loadAll(of type: KeyType? = nil) -> [EncryptionKey] {
        migrateLegacyMetadataIfNeeded()

        // Attributes only — never kSecReturnData, so enumerating the vault
        // neither authenticates nor puts a secret in memory. Browsing the list
        // stays silent; revealing one is what asks for Touch ID.
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecMatchLimit: kSecMatchLimitAll,
            kSecReturnAttributes: true,
            kSecReturnData: false,
            kSecUseDataProtectionKeychain: false
        ]

        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let items = result as? [[CFString: Any]] else {
            return []
        }

        return items
            .compactMap(key(from:))
            .filter { type == nil || $0.type == type }
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    private static func key(from item: [CFString: Any]) -> EncryptionKey? {
        guard let account = item[kSecAttrAccount] as? String,
              let id = UUID(uuidString: account) else { return nil }

        // An item written before metadata moved into the Keychain has no
        // description; treat it as an API key, which is all the old scheme
        // could produce.
        let type = (item[kSecAttrDescription] as? String)
            .flatMap(KeyType.init(rawValue:)) ?? .api
        guard ownedTypes.contains(type) else { return nil }

        let meta = (item[kSecAttrComment] as? String)
            .flatMap { $0.data(using: .utf8) }
            .flatMap { try? JSONDecoder().decode(StoredMeta.self, from: $0) }

        return EncryptionKey(
            id: id,
            type: type,
            name: item[kSecAttrLabel] as? String ?? "(unnamed)",
            service: meta?.service,
            notes: meta?.notes,
            createdDate: meta?.createdDate,
            hasPrivateKey: false
        )
    }

    // MARK: - Migration

    /// Back-fill Keychain attributes for items written under the old scheme, so
    /// the plist stops being load-bearing. Runs once, and is safe to re-run:
    /// it only ever adds attributes to items that already exist.
    static func migrateLegacyMetadataIfNeeded() {
        guard !UserDefaults.standard.bool(forKey: migrationDoneKey) else { return }
        let legacy = loadLegacyMetaDict()
        guard !legacy.isEmpty else {
            UserDefaults.standard.set(true, forKey: migrationDoneKey)
            return
        }

        for (uuidString, meta) in legacy {
            guard let id = UUID(uuidString: uuidString) else { continue }
            let key = EncryptionKey(
                id: id,
                type: .api,
                name: meta.name,
                service: meta.service,
                notes: meta.notes,
                createdDate: meta.createdDate,
                hasPrivateKey: false
            )
            // Best effort: an entry whose Keychain item is already gone just
            // has nothing to update, and must not block the rest.
            _ = try? update(key, newSecret: nil)
        }
        UserDefaults.standard.set(true, forKey: migrationDoneKey)
    }

    // MARK: - Helpers

    private static func baseQuery(id: UUID) -> [CFString: Any] {
        // Explicit rather than defaulted: "which keychain did that item land
        // in" is not a question to leave to an SDK default in a store of
        // things that cannot be re-created.
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: id.uuidString,
            kSecUseDataProtectionKeychain: false
        ]
    }

    private static func attributes(for key: EncryptionKey) -> [CFString: Any] {
        var attrs: [CFString: Any] = [
            kSecAttrLabel: key.name,
            kSecAttrDescription: key.type.rawValue
        ]
        let meta = StoredMeta(service: key.service,
                              notes: key.notes,
                              createdDate: key.createdDate ?? Date())
        if let data = try? JSONEncoder().encode(meta),
           let json = String(data: data, encoding: .utf8) {
            attrs[kSecAttrComment] = json
        }
        return attrs
    }

    private struct LegacyMeta: Codable {
        var name: String
        var service: String?
        var notes: String?
        var createdDate: Date?
    }

    private static func loadLegacyMetaDict() -> [String: LegacyMeta] {
        guard let data = UserDefaults.standard.data(forKey: legacyMetaDefaultsKey),
              let dict = try? JSONDecoder().decode([String: LegacyMeta].self, from: data) else {
            return [:]
        }
        return dict
    }

    private static func saveLegacyMetaDict(_ dict: [String: LegacyMeta]) {
        guard let data = try? JSONEncoder().encode(dict) else { return }
        UserDefaults.standard.set(data, forKey: legacyMetaDefaultsKey)
    }
}
