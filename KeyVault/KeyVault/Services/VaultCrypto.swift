import CommonCrypto
import CryptoKit
import Foundation
import Security

/// Encrypts the secrets `SecretStore` owns, under a key derived from a master
/// passphrase, so that what lands in the Keychain is ciphertext.
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
    static let magic = Data("KVENC1\0".utf8)

    /// OWASP's floor for PBKDF2-HMAC-SHA256. Deliberately slow: it is the only
    /// thing standing between a stolen ciphertext and an offline guessing run.
    private static let iterations: UInt32 = 600_000
    private static let keyBytes = 32
    private static let saltBytes = 32

    private static let saltAccount = "io.github.sevmorris.KeyVault.salt"
    private static let verifierAccount = "io.github.sevmorris.KeyVault.verifier"
    private static let verifierPlaintext = Data("KeyVault verifier v1".utf8)

    enum CryptoError: LocalizedError {
        case locked
        case wrongPassphrase
        case malformed
        case keychain(OSStatus)

        var errorDescription: String? {
            switch self {
            case .locked:         return "The vault is locked."
            case .wrongPassphrase: return "That passphrase is not correct."
            case .malformed:      return "This secret is not in a format KeyVault recognises."
            case .keychain(let s):
                let detail = SecCopyErrorMessageString(s, nil) as String?
                return detail.map { "Keychain error: \($0)" } ?? "Keychain error (OSStatus \(s))"
            }
        }
    }

    // MARK: - Session

    /// Held only while unlocked. Never written anywhere: the whole point is that
    /// the disk holds ciphertext and a salt, and nothing that decrypts them.
    private static var sessionKey: SymmetricKey?

    /// Set aside by `suspend()`, and the only thing that makes a Touch ID
    /// resume possible. It is still just memory — nothing here is ever written
    /// down, which is why this can only bring back a vault that was open in
    /// this same run of the app.
    private static var suspendedKey: SymmetricKey?

    static var isUnlocked: Bool { sessionKey != nil }

    /// True when the vault was closed by the idle timer rather than forgotten.
    static var isSuspended: Bool { suspendedKey != nil }

    /// True once a passphrase has been set — i.e. a salt and verifier exist.
    static var isConfigured: Bool { loadBlob(account: saltAccount) != nil }

    /// A real lock: the key is gone, and only the passphrase derives it again.
    static func lock() {
        sessionKey = nil
        suspendedKey = nil
    }

    /// The one place a key becomes the session key, so "at most one copy of it
    /// exists" holds by construction. A passphrase unlock after an idle lock
    /// has to drop the suspended copy: leaving it there would keep a second
    /// key in memory for the life of the process, and leave the vault
    /// describing itself as resumable when it had already been reopened.
    private static func adopt(_ key: SymmetricKey) {
        sessionKey = key
        suspendedKey = nil
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
        guard let key = sessionKey else { return }
        suspendedKey = key
        sessionKey = nil
    }

    /// Put a suspended key back. Authenticating is the caller's job; this only
    /// moves the key, and does nothing at all if the vault was properly locked.
    @discardableResult
    static func resume() -> Bool {
        guard let key = suspendedKey else { return false }
        adopt(key)
        return true
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
        let sealed = try AES.GCM.seal(verifierPlaintext, using: key)
        guard let verifier = sealed.combined else { throw CryptoError.malformed }

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
        guard let box = try? AES.GCM.SealedBox(combined: verifier),
              let opened = try? AES.GCM.open(box, using: key),
              opened == verifierPlaintext else {
            return false
        }
        adopt(key)
        return true
    }

    // MARK: - Encrypt / decrypt

    static func encrypt(_ plaintext: String) throws -> Data {
        guard let key = sessionKey else { throw CryptoError.locked }
        let sealed = try AES.GCM.seal(Data(plaintext.utf8), using: key)
        guard let combined = sealed.combined else { throw CryptoError.malformed }
        return magic + combined
    }

    static func decrypt(_ blob: Data) throws -> String {
        guard isEncrypted(blob) else { throw CryptoError.malformed }
        guard let key = sessionKey else { throw CryptoError.locked }
        let body = blob.dropFirst(magic.count)
        guard let box = try? AES.GCM.SealedBox(combined: body),
              let opened = try? AES.GCM.open(box, using: key),
              let text = String(data: opened, encoding: .utf8) else {
            throw CryptoError.wrongPassphrase
        }
        return text
    }

    static func isEncrypted(_ blob: Data) -> Bool {
        blob.count > magic.count && blob.prefix(magic.count) == magic
    }

    // MARK: - Internals

    private static func derive(passphrase: String, salt: Data) throws -> SymmetricKey {
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
