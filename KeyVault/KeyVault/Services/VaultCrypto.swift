import CommonCrypto
import CryptoKit
import Foundation
import Security

/// Encrypts the secrets `SecretStore` owns, under a key derived from a master
/// passphrase, so that what lands in the Keychain is ciphertext. The files
/// `FileStore` keeps are sealed under the same key.
///
/// Why this exists rather than a Keychain access control or a Secure Enclave
/// key, both of which would be less to remember:
///
///   kSecAttrAccessControl is silently ignored on the macOS *legacy* keychain —
///   SecItemAdd and SecItemUpdate both return errSecSuccess and the secret
///   still reads straight back with no prompt. It is a data-protection keychain
///   feature. Reaching that keychain, or persisting a Secure Enclave key,
///   requires an application identifier from a provisioning profile, and both
///   fail with -34018 without one. Measured, not assumed:
///
///     ad-hoc, kSecUseDataProtectionKeychain              -> -34018
///     Developer ID signed, no entitlement                -> -34018
///     Developer ID + keychain-access-groups, no profile  -> killed on launch
///     persistent Secure Enclave key, no entitlement      -> -34018
///
/// So protection cannot come from the Keychain here. It comes from the payload
/// being encrypted before it is ever handed over — which has the side benefit
/// of being portable, where an Enclave key would have bound the vault to one
/// machine.
enum VaultCrypto {
    /// Marks a stored blob as ciphertext. A vault written before this existed
    /// holds plain UTF-8, and must keep reading correctly until it is migrated,
    /// so the two have to be distinguishable with certainty rather than by
    /// guessing whether some bytes look like text.
    ///
    /// Version 2 seals the item's id in as authenticated data, so a payload
    /// opens only under the Keychain item it was written to. Version 1 did
    /// not: anything that could write to the login keychain — every process
    /// running as you, since the ciphertext's ACL is open — could copy one
    /// item's payload over another's, and the vault would show the copied
    /// secret under the other name without complaint. Version 1 is still read,
    /// and becomes version 2 when its secret is next saved, or when Settings'
    /// Repair Keychain Access sweeps the vault.
    static let magicV1 = Data("KVENC1\0".utf8)
    static let magicV2 = Data("KVENC2\0".utf8)

    /// OWASP's floor for PBKDF2-HMAC-SHA256. Deliberately slow: it is the only
    /// thing standing between a stolen ciphertext and an offline guessing run.
    private static let iterations: UInt32 = 600_000
    private static let keyBytes = 32
    private static let saltBytes = 32

    private static let saltAccount = "io.github.sevmorris.KeyVault.salt"
    private static let verifierAccount = "io.github.sevmorris.KeyVault.verifier"
    private static let verifierPlaintext = Data("KeyVault verifier v1".utf8)
    /// A passphrase change in progress. See `PassphraseChange`.
    private static let pendingSaltAccount = "io.github.sevmorris.KeyVault.salt.pending"
    private static let pendingVerifierAccount = "io.github.sevmorris.KeyVault.verifier.pending"

    enum CryptoError: LocalizedError {
        case locked
        case wrongPassphrase
        case malformed
        /// A sealed blob the vault key will not open. Not `wrongPassphrase`:
        /// nobody typed one, and the vault it came from is open.
        case authenticationFailed
        case keychain(OSStatus)

        var errorDescription: String? {
            switch self {
            case .locked:         return "The vault is locked."
            case .wrongPassphrase: return "That passphrase is not correct."
            case .malformed:      return "This secret is not in a format KeyVault recognises."
            case .authenticationFailed:
                return "The vault's key does not open this. It was written under a different "
                    + "passphrase, or it has been damaged since."
            case .keychain(let s):
                let detail = SecCopyErrorMessageString(s, nil) as String?
                return detail.map { "Keychain error: \($0)" } ?? "Keychain error (OSStatus \(s))"
            }
        }
    }

    // MARK: - Session

    /// Guards `sessionKey` and `suspendedKey`, which more than one thread
    /// touches: the passphrase is derived and adopted on a detached task so
    /// the window keeps drawing, the export reads the key on its own actor,
    /// and the main thread locks, suspends and resumes. On a Mac with ten or
    /// more cores those run at the same moment, and an unguarded Optional
    /// holding a reference can be read while another thread releases it.
    ///
    /// Held for the read or the swap and nothing longer — never across a
    /// derivation or a seal — and never taken twice: NSLock is not recursive,
    /// so nothing called inside `withSession` may call it again.
    private static let sessionLock = NSLock()

    /// Held only while unlocked. Never written anywhere: the whole point is that
    /// the disk holds ciphertext and a salt, and nothing that decrypts them.
    /// Read and written only inside `withSession`.
    ///
    /// `nonisolated(unsafe)` because the compiler cannot see a lock: to Swift 6
    /// this is unprotected global state, and it is `sessionLock` that makes it
    /// otherwise. Any access outside `withSession` is a data race.
    nonisolated(unsafe) private static var sessionKey: SymmetricKey?

    /// Set aside by `suspend()`, and the only thing that makes a Touch ID
    /// resume possible. It is still just memory — nothing here is ever written
    /// down, which is why this can only bring back a vault that was open in
    /// this same run of the app. Read and written only inside `withSession`,
    /// and `nonisolated(unsafe)` for the same reason as `sessionKey`.
    nonisolated(unsafe) private static var suspendedKey: SymmetricKey?

    private static func withSession<T>(_ body: () throws -> T) rethrows -> T {
        sessionLock.lock()
        defer { sessionLock.unlock() }
        return try body()
    }

    static var isUnlocked: Bool { withSession { sessionKey != nil } }

    /// True when the vault was closed by the idle timer rather than forgotten.
    static var isSuspended: Bool { withSession { suspendedKey != nil } }

    /// True once a passphrase has been set — i.e. a salt and verifier exist.
    static var isConfigured: Bool { loadBlob(account: saltAccount) != nil }

    /// A real lock: the key is gone, and only the passphrase derives it again.
    static func lock() {
        withSession {
            sessionKey = nil
            suspendedKey = nil
        }
    }

    /// The one place a key becomes the session key, so "at most one copy of it
    /// exists" holds by construction. A passphrase unlock after an idle lock
    /// has to drop the suspended copy: leaving it there would keep a second
    /// key in memory for the life of the process, and leave the vault
    /// describing itself as resumable when it had already been reopened.
    private static func adopt(_ key: SymmetricKey) {
        withSession {
            sessionKey = key
            suspendedKey = nil
        }
    }

    /// The key to seal or open with. Taken under the lock and used outside
    /// it, so a large file's encryption never holds up a lock or an unlock.
    ///
    /// Internal rather than private for `FileStore`, which seals with this
    /// key in the app and with one it is handed in a test. Nothing may write
    /// it anywhere.
    static func currentKey() throws -> SymmetricKey {
        guard let key = withSession({ sessionKey }) else { throw CryptoError.locked }
        return key
    }

    /// The idle lock. Deliberately weaker than `lock()` — it hides the vault
    /// rather than forgetting it, holding the key in memory so a fingerprint
    /// can put it back.
    ///
    /// The distinction is the whole reason Touch ID can be offered at all. A
    /// fingerprint is a yes/no, not a secret to derive a key from, so unlocking
    /// with one at cold start would mean keeping the key on disk — which is
    /// exactly what this file exists to avoid. Within one run there is already
    /// a key in memory, so nothing new is written anywhere.
    static func suspend() {
        withSession {
            guard let key = sessionKey else { return }
            suspendedKey = key
            sessionKey = nil
        }
    }

    /// Put a suspended key back. Authenticating is the caller's job; this only
    /// moves the key, and does nothing at all if the vault was properly locked.
    ///
    /// Inline rather than through `adopt`, which takes the lock itself and
    /// would deadlock here. The check and the move have to be one step
    /// anyway: split, a passphrase unlock landing between them would be
    /// undone by the key it had just replaced.
    @discardableResult
    static func resume() -> Bool {
        withSession {
            guard let key = suspendedKey else { return false }
            sessionKey = key
            suspendedKey = nil
            return true
        }
    }

    // MARK: - Passphrase

    /// First-time setup. Generates the salt, derives the key, and stores a
    /// verifier so a later wrong passphrase is reported as such rather than
    /// producing garbage that looks like a corrupt vault.
    static func configure(passphrase: String) throws {
        var salt = Data(count: saltBytes)
        let ok = salt.withUnsafeMutableBytes { buf in
            SecRandomCopyBytes(kSecRandomDefault, saltBytes, buf.baseAddress!) == errSecSuccess
        }
        guard ok else { throw CryptoError.keychain(errSecAllocate) }

        let key = try derive(passphrase: passphrase, salt: salt)
        let verifier = try makeVerifier(using: key)

        try storeBlob(salt, account: saltAccount)
        try storeBlob(verifier, account: verifierAccount)
        adopt(key)
    }

    /// Derive and check against the stored verifier. Returns false rather than
    /// throwing for a wrong passphrase, which is an expected answer, not a fault.
    @discardableResult
    static func unlock(passphrase: String) throws -> Bool {
        guard let salt = loadBlob(account: saltAccount),
              let verifier = loadBlob(account: verifierAccount) else {
            throw CryptoError.locked
        }
        let key = try derive(passphrase: passphrase, salt: salt)
        guard Self.verifier(verifier, accepts: key) else { return false }
        adopt(key)
        return true
    }

    /// The verifier for a key: a known plaintext sealed under it, which only
    /// that key opens. Stored beside the salt.
    static func makeVerifier(using key: SymmetricKey) throws -> Data {
        guard let combined = try AES.GCM.seal(verifierPlaintext, using: key).combined else {
            throw CryptoError.malformed
        }
        return combined
    }

    static func verifier(_ verifier: Data, accepts key: SymmetricKey) -> Bool {
        guard let box = try? AES.GCM.SealedBox(combined: verifier),
              let opened = try? AES.GCM.open(box, using: key) else { return false }
        return opened == verifierPlaintext
    }

    // MARK: - Changing the passphrase

    // The Keychain half of `PassphraseChange`, through `KeychainRekeyBackend`.
    // The ordering that keeps a change safe to interrupt lives there.

    static func vaultBlobs() -> (salt: Data, verifier: Data)? {
        guard let salt = loadBlob(account: saltAccount),
              let verifier = loadBlob(account: verifierAccount) else { return nil }
        return (salt, verifier)
    }

    static func pendingBlobs() -> (salt: Data, verifier: Data)? {
        guard let salt = loadBlob(account: pendingSaltAccount),
              let verifier = loadBlob(account: pendingVerifierAccount) else { return nil }
        return (salt, verifier)
    }

    /// Verifier first, salt last: `pendingBlobs` needs both, so a pending
    /// record half written reads as none at all.
    static func writePending(salt: Data, verifier: Data) throws {
        try storeBlob(verifier, account: pendingVerifierAccount)
        try storeBlob(salt, account: pendingSaltAccount)
    }

    /// Salt first, for the same reason.
    static func deletePending() {
        deleteBlob(account: pendingSaltAccount)
        deleteBlob(account: pendingVerifierAccount)
    }

    static func updateSalt(_ salt: Data) throws { try updateBlob(salt, account: saltAccount) }
    static func updateVerifier(_ verifier: Data) throws { try updateBlob(verifier, account: verifierAccount) }

    /// After a change, the new key becomes the session key, so the vault
    /// stays open under the passphrase just set.
    static func adoptChangedKey(_ key: SymmetricKey) { adopt(key) }

    // MARK: - Encrypt / decrypt

    // Each operation comes twice: once under the session key, which is what
    // the app uses, and once under a key it is handed. The second is how a
    // test exercises the real format without a passphrase in the Keychain,
    // and it is the same code, not a copy of it.

    /// Seal a secret for the item `id`. Always version 2.
    static func encrypt(_ plaintext: String, for id: UUID) throws -> Data {
        try encrypt(plaintext, for: id, using: currentKey())
    }

    static func encrypt(_ plaintext: String, for id: UUID, using key: SymmetricKey) throws -> Data {
        let sealed = try AES.GCM.seal(Data(plaintext.utf8), using: key,
                                      authenticating: itemContext(id))
        guard let combined = sealed.combined else { throw CryptoError.malformed }
        return magicV2 + combined
    }

    static func decrypt(_ blob: Data, for id: UUID) throws -> String {
        guard isEncrypted(blob) else { throw CryptoError.malformed }
        return try decrypt(blob, for: id, using: currentKey())
    }

    /// Either version. A version 2 payload under the wrong item fails the
    /// same way as one under the wrong key: AES-GCM cannot tell them apart,
    /// and the wrong key is by far the likelier.
    static func decrypt(_ blob: Data, for id: UUID, using key: SymmetricKey) throws -> String {
        let opened: Data?
        if blob.starts(with: magicV2) {
            let box = try? AES.GCM.SealedBox(combined: blob.dropFirst(magicV2.count))
            opened = box.flatMap { try? AES.GCM.open($0, using: key, authenticating: itemContext(id)) }
        } else if blob.starts(with: magicV1) {
            let box = try? AES.GCM.SealedBox(combined: blob.dropFirst(magicV1.count))
            opened = box.flatMap { try? AES.GCM.open($0, using: key) }
        } else {
            throw CryptoError.malformed
        }
        guard let opened, let text = String(data: opened, encoding: .utf8) else {
            throw CryptoError.wrongPassphrase
        }
        return text
    }

    static func isEncrypted(_ blob: Data) -> Bool {
        [magicV1, magicV2].contains { blob.count > $0.count && blob.starts(with: $0) }
    }

    /// Whether a payload predates binding to its item.
    static func isVersion1(_ blob: Data) -> Bool {
        blob.count > magicV1.count && blob.starts(with: magicV1)
    }

    /// What a version 2 payload is sealed against: the format and the item.
    private static func itemContext(_ id: UUID) -> Data {
        magicV2 + id.bytes
    }

    // MARK: - Bytes

    /// Seal bytes rather than text, for `FileStore`. No magic prefix: the file
    /// format carries its own.
    ///
    /// `context` is authenticated but not encrypted, so a sealed blob opens
    /// only alongside the same context it was sealed with. FileStore passes
    /// the item's id, which is what stops one file's contents being moved into
    /// another file and opening there as if they belonged.
    static func seal(_ plaintext: Data, authenticating context: Data) throws -> Data {
        try seal(plaintext, authenticating: context, using: currentKey())
    }

    static func seal(_ plaintext: Data, authenticating context: Data,
                     using key: SymmetricKey) throws -> Data {
        let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: context)
        guard let combined = sealed.combined else { throw CryptoError.malformed }
        return combined
    }

    static func open(_ combined: Data, authenticating context: Data) throws -> Data {
        try open(combined, authenticating: context, using: currentKey())
    }

    static func open(_ combined: Data, authenticating context: Data,
                     using key: SymmetricKey) throws -> Data {
        guard let box = try? AES.GCM.SealedBox(combined: combined),
              let opened = try? AES.GCM.open(box, using: key, authenticating: context) else {
            throw CryptoError.authenticationFailed
        }
        return opened
    }

    // MARK: - Internals

    /// Internal so a test can pin it to a known answer: a change here would
    /// derive a different key from the same passphrase, and every vault
    /// written before it would stop opening.
    static func derive(passphrase: String, salt: Data) throws -> SymmetricKey {
        var derived = Data(count: keyBytes)
        let status = derived.withUnsafeMutableBytes { out in
            salt.withUnsafeBytes { saltBuf in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passphrase, passphrase.utf8.count,
                    saltBuf.baseAddress!.assumingMemoryBound(to: UInt8.self), salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    iterations,
                    out.baseAddress!.assumingMemoryBound(to: UInt8.self), keyBytes
                )
            }
        }
        guard status == kCCSuccess else { throw CryptoError.keychain(errSecParam) }
        return SymmetricKey(data: derived)
    }

    /// Salt and verifier live in the Keychain beside the secrets. Neither is
    /// confidential — a salt is not a secret, and the verifier only proves a
    /// passphrase is right, it does not reveal it — so they are stored plainly
    /// and are readable by anything that can read the Keychain. That is fine.
    private static func storeBlob(_ data: Data, account: String) throws {
        let base: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: SecretStore.keychainService,
            kSecAttrAccount: account,
            kSecUseDataProtectionKeychain: false
        ]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData] = data
        add[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlocked
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw CryptoError.keychain(status) }
    }

    /// In place, so the item is never absent. `storeBlob` deletes and adds,
    /// which is fine for a first write and wrong for the salt of a vault that
    /// already holds secrets.
    private static func updateBlob(_ data: Data, account: String) throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: SecretStore.keychainService,
            kSecAttrAccount: account,
            kSecUseDataProtectionKeychain: false
        ]
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData: data] as CFDictionary)
        guard status == errSecSuccess else { throw CryptoError.keychain(status) }
        guard loadBlob(account: account) == data else { throw CryptoError.keychain(errSecIO) }
    }

    private static func deleteBlob(account: String) {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: SecretStore.keychainService,
            kSecAttrAccount: account,
            kSecUseDataProtectionKeychain: false
        ]
        SecItemDelete(query as CFDictionary)
    }

    private static func loadBlob(account: String) -> Data? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: SecretStore.keychainService,
            kSecAttrAccount: account,
            kSecUseDataProtectionKeychain: false,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }
}

extension UUID {
    /// The sixteen bytes of the UUID, in order. What both stores bind
    /// ciphertext to.
    var bytes: Data { withUnsafeBytes(of: uuid) { Data($0) } }
}
