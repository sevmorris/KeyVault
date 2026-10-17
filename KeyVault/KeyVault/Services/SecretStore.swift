import Foundation
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
    private static let legacyMetaDefaultsKey = "APIKeyMeta"
    private static let migrationDoneKey = "SecretStoreMetadataMigrated"

    /// The fields that don't have a dedicated Keychain attribute.
    private struct StoredMeta: Codable {
        var service: String?
        var notes: String?
        var createdDate: Date?
        /// Added after the first vaults were written, so it must decode as nil
        /// from a comment blob that predates it. Optional does that for free.
        var category: String?
    }

    /// Types this store owns. SSH/GPG/Age are handled by their own services.
    static let ownedTypes: Set<KeyType> = [.api, .note]

    // MARK: - Protection
    //
    // The payload of every item is encrypted by VaultCrypto before it reaches
    // the Keychain, so a Keychain dump yields ciphertext. That is the only
    // mechanism available here — see VaultCrypto for why the two obvious
    // Keychain-native options are both unreachable without a provisioning
    // profile, and why an earlier attempt using kSecAttrAccessControl reported
    // success while protecting nothing.
    //
    // Items written before the passphrase was set are plain UTF-8 and still
    // read correctly; VaultCrypto.isEncrypted tells the two apart on a magic
    // header rather than by guessing.

    // MARK: - Keychain access

    /// An access object trusting any application, applied to every item whose
    /// payload is ciphertext — and only to those. See `acl(forPayload:)`.
    ///
    /// The Keychain ACL on such an item guards bytes that are useless without
    /// the master passphrase, while charging a confirmation dialog per item
    /// whenever the asking binary's code identity differs from the one that
    /// wrote it. That is not hypothetical: the encryption sweep ran from a
    /// locally built copy, re-stamped all 22 items with that identity, and the
    /// released build then had to ask for every one of them during an export.
    ///
    /// Security here is the passphrase and a 600k-iteration KDF, not the ACL.
    ///
    /// Verified structurally rather than by watching for dialogs — with this,
    /// every ACL on the stored item reports a NULL trusted-application list;
    /// without it, the decrypt ACL names exactly one.
    private static func permissiveAccess() -> SecAccess? {
        var access: SecAccess?
        guard SecAccessCreate("KeyVault" as CFString, nil, &access) == errSecSuccess,
              let access else { return nil }

        var aclList: CFArray?
        guard SecAccessCopyACLList(access, &aclList) == errSecSuccess,
              let acls = aclList as? [SecACL] else { return nil }

        for acl in acls {
            var apps: CFArray?
            var description: CFString?
            var prompt = SecKeychainPromptSelector()
            guard SecACLCopyContents(acl, &apps, &description, &prompt) == errSecSuccess else { continue }
            // A NULL application list is what the Keychain reads as "any
            // application"; the default is the creating binary alone.
            SecACLSetContents(acl, nil, description ?? ("KeyVault" as CFString), prompt)
        }
        return access
    }

    /// The Keychain's own default: given no list of trusted applications,
    /// SecAccessCreate trusts the one calling it, and any other app that asks
    /// for the item has to be allowed at a prompt.
    private static func ownAccess() -> SecAccess? {
        var access: SecAccess?
        guard SecAccessCreate("KeyVault" as CFString, nil, &access) == errSecSuccess else { return nil }
        return access
    }

    /// The ACL a payload calls for.
    ///
    /// Ciphertext is opened to any application: the passphrase protects it,
    /// and the ACL would only add a dialog per item. Plain text is kept to
    /// this app alone. Before a passphrase is set, the Keychain's prompt is the
    /// only thing between a note and every other process running as you, and
    /// every write used to open the ACL regardless — so in the state the app
    /// starts in, any process could read every secret without being asked.
    private static func acl(forPayload payload: Data) -> SecAccess? {
        VaultCrypto.isEncrypted(payload) ? permissiveAccess() : ownAccess()
    }

    // MARK: - Write

    static func save(_ key: EncryptionKey, secret: String) throws {
        guard let secretData = secret.data(using: .utf8) else {
            throw KeyError.keychainError(errSecParam)
        }

        var query = baseQuery(id: key.id)
        let payload = try protectedPayload(secretData, for: key.id)
        query[kSecValueData] = payload
        query[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlocked
        if let access = acl(forPayload: payload) { query[kSecAttrAccess] = access }
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
            let payload = try protectedPayload(data, for: key.id)
            changes[kSecValueData] = payload
            // Editing an item written before the passphrase was set encrypts
            // it on the way back down, so the vault protects itself as you
            // touch it, and the ACL follows what is now stored.
            if let access = acl(forPayload: payload) { changes[kSecAttrAccess] = access }
        }
        // A change to metadata alone leaves the ACL as it is. Which ACL is
        // right depends on the payload, and reading the payload just to decide
        // would make filing a note read the secret it holds.

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

    // MARK: - Encryption migration

    /// Encrypt every item still stored as plaintext.
    ///
    /// Deliberately NOT automatic. It is one-way — afterwards the vault cannot
    /// be read without the passphrase — and an earlier automatic sweep in this
    /// file recorded success while doing nothing at all. This one is invoked
    /// explicitly, after an export, and reports what it actually did.
    ///
    /// Each item is one SecItemUpdate of its payload, so the work is atomic per
    /// item and an interruption leaves the rest untouched and re-runnable.
    @discardableResult
    static func encryptExistingSecrets() throws -> (encrypted: Int, alreadyDone: Int, failed: Int) {
        guard VaultCrypto.isUnlocked else { throw VaultCrypto.CryptoError.locked }

        var encrypted = 0, alreadyDone = 0, failed = 0

        for id in allAccountIDs() {
            guard let blob = rawPayload(for: id) else { failed += 1; continue }
            if VaultCrypto.isEncrypted(blob) {
                // Already ciphertext, but it may still carry the restrictive ACL
                // a previous build stamped on it. Relaxing costs one update and
                // saves a dialog per item on every future export.
                relaxAccess(for: id)
                if VaultCrypto.isVersion1(blob) { upgradeToVersion2(id: id, payload: blob) }
                alreadyDone += 1
                continue
            }

            guard let plaintext = String(data: blob, encoding: .utf8),
                  let sealed = try? VaultCrypto.encrypt(plaintext, for: id) else {
                failed += 1
                continue
            }
            // Ciphertext now, so its ACL opens with it. Plain text was kept to
            // this app alone, and left that way it would bring back a dialog
            // per item whenever a differently signed build reads the vault.
            var changes: [CFString: Any] = [kSecValueData: sealed]
            if let access = permissiveAccess() { changes[kSecAttrAccess] = access }
            let status = SecItemUpdate(baseQuery(id: id) as CFDictionary,
                                       changes as CFDictionary)
            if status == errSecSuccess {
                // Read back before counting it: this file has already shipped a
                // sweep that trusted errSecSuccess and protected nothing. And
                // opened, not just recognised: ciphertext that does not give
                // back the secret is a secret lost.
                if let check = rawPayload(for: id),
                   (try? VaultCrypto.decrypt(check, for: id)) == plaintext {
                    encrypted += 1
                } else {
                    failed += 1
                }
            } else {
                failed += 1
            }
        }
        return (encrypted, alreadyDone, failed)
    }

    /// Re-seal a version 1 payload as version 2, binding it to its item. See
    /// `VaultCrypto.magicV2`.
    ///
    /// Best-effort, like `relaxAccess`: a version 1 payload is still sealed
    /// under the passphrase, so one that will not upgrade is left as it is
    /// rather than failing the sweep. Written only once it has opened, and
    /// read back and opened again afterwards; if that fails, the payload it
    /// replaced is put back.
    private static func upgradeToVersion2(id: UUID, payload: Data) {
        guard let plaintext = try? VaultCrypto.decrypt(payload, for: id),
              let sealed = try? VaultCrypto.encrypt(plaintext, for: id),
              SecItemUpdate(baseQuery(id: id) as CFDictionary,
                            [kSecValueData: sealed] as CFDictionary) == errSecSuccess else { return }
        if let check = rawPayload(for: id), (try? VaultCrypto.decrypt(check, for: id)) == plaintext {
            return
        }
        _ = SecItemUpdate(baseQuery(id: id) as CFDictionary, [kSecValueData: payload] as CFDictionary)
    }

    /// Widen one item's ACL to any application. Best-effort: an item that
    /// refuses is left alone rather than failing the sweep, because the ACL is
    /// convenience and the encryption is the protection.
    private static func relaxAccess(for id: UUID) {
        guard let access = permissiveAccess() else { return }
        _ = SecItemUpdate(baseQuery(id: id) as CFDictionary,
                          [kSecAttrAccess: access] as CFDictionary)
    }

    /// Close the ACL on every plaintext item an earlier build opened to any
    /// application, so other apps have to ask for it again.
    ///
    /// Run once a launch. Only items whose ACL is open are read at all, and
    /// reading an open item never prompts; ciphertext among them is left
    /// open, which is its intended state. Re-runnable, and cheap once there is
    /// nothing left to close. Counted only once the ACL reads back closed,
    /// because a Keychain write reporting success has fooled this file before.
    @discardableResult
    static func restrictPlaintextAccess() -> (restricted: Int, failed: Int) {
        var restricted = 0, failed = 0
        for id in allAccountIDs() where isOpenToAnyApplication(id: id) {
            guard let blob = rawPayload(for: id) else { failed += 1; continue }
            guard !VaultCrypto.isEncrypted(blob) else { continue }
            guard let access = ownAccess(),
                  SecItemUpdate(baseQuery(id: id) as CFDictionary,
                                [kSecAttrAccess: access] as CFDictionary) == errSecSuccess,
                  !isOpenToAnyApplication(id: id) else {
                failed += 1
                continue
            }
            restricted += 1
        }
        return (restricted, failed)
    }

    /// Whether any application may decrypt an item without being asked: the
    /// NULL application list `permissiveAccess()` writes on its decrypt ACL.
    /// Read from the item's access object, which prompts for nothing —
    /// looking at an ACL is not reading the secret behind it.
    private static func isOpenToAnyApplication(id: UUID) -> Bool {
        var query = baseQuery(id: id)
        query[kSecReturnRef] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let result, CFGetTypeID(result) == SecKeychainItemGetTypeID() else { return false }

        var access: SecAccess?
        guard SecKeychainItemCopyAccess(result as! SecKeychainItem, &access) == errSecSuccess,
              let access else { return false }
        var aclList: CFArray?
        guard SecAccessCopyACLList(access, &aclList) == errSecSuccess,
              let acls = aclList as? [SecACL] else { return false }

        let decrypt = kSecACLAuthorizationDecrypt as String
        let any = kSecACLAuthorizationAny as String
        return acls.contains { acl in
            let authorizations = SecACLCopyAuthorizations(acl) as? [String] ?? []
            guard authorizations.contains(decrypt) || authorizations.contains(any) else { return false }
            var apps: CFArray?
            var description: CFString?
            var prompt = SecKeychainPromptSelector()
            guard SecACLCopyContents(acl, &apps, &description, &prompt) == errSecSuccess else { return false }
            return apps == nil
        }
    }

    /// How many items are still stored as plaintext.
    static func plaintextCount() -> Int {
        allAccountIDs().reduce(into: 0) { count, id in
            if let blob = rawPayload(for: id), !VaultCrypto.isEncrypted(blob) { count += 1 }
        }
    }

    /// Account UUIDs for every item this store owns. The salt and verifier
    /// VaultCrypto keeps alongside them are filtered out for free: their
    /// accounts are names, not UUIDs.
    private static func allAccountIDs() -> [UUID] {
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
        return items.compactMap {
            ($0[kSecAttrAccount] as? String).flatMap(UUID.init(uuidString:))
        }
    }

    private static func rawPayload(for id: UUID) -> Data? {
        var query = baseQuery(id: id)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    /// Encrypt when a passphrase is configured and the vault is open. Before
    /// that, storage is plaintext exactly as it always was — the app has to
    /// keep working for someone who has not set one yet.
    private static func protectedPayload(_ plaintext: Data, for id: UUID) throws -> Data {
        guard VaultCrypto.isConfigured else { return plaintext }
        guard VaultCrypto.isUnlocked else { throw VaultCrypto.CryptoError.locked }
        guard let text = String(data: plaintext, encoding: .utf8) else {
            throw KeyError.keychainError(errSecParam)
        }
        return try VaultCrypto.encrypt(text, for: id)
    }

    // MARK: - Read

    /// Reading the payload is what triggers authentication — `loadAll` reads
    /// attributes only and stays silent, so browsing the list never prompts and
    /// revealing a secret does.
    static func loadSecret(for id: UUID) throws -> String {
        guard let data = rawPayload(for: id) else {
            throw KeyError.keychainError(errSecItemNotFound)
        }
        if VaultCrypto.isEncrypted(data) {
            return try VaultCrypto.decrypt(data, for: id)
        }
        // Written before a passphrase was set. Still readable, and still
        // exposed — encryptExistingSecrets() is what fixes that.
        guard let secret = String(data: data, encoding: .utf8) else {
            throw KeyError.keychainError(errSecDecode)
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
            category: meta?.category,
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
        guard !UserDefaults.app.bool(forKey: migrationDoneKey) else { return }
        let legacy = loadLegacyMetaDict()
        guard !legacy.isEmpty else {
            UserDefaults.app.set(true, forKey: migrationDoneKey)
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
        UserDefaults.app.set(true, forKey: migrationDoneKey)
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
                              createdDate: key.createdDate ?? Date(),
                              category: key.category)
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
        guard let data = UserDefaults.app.data(forKey: legacyMetaDefaultsKey),
              let dict = try? JSONDecoder().decode([String: LegacyMeta].self, from: data) else {
            return [:]
        }
        return dict
    }

    private static func saveLegacyMetaDict(_ dict: [String: LegacyMeta]) {
        guard let data = try? JSONEncoder().encode(dict) else { return }
        UserDefaults.app.set(data, forKey: legacyMetaDefaultsKey)
    }
}
