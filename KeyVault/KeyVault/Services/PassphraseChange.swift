import CryptoKit
import Foundation

/// Where a passphrase change reads and writes the Keychain's half of the
/// vault: the salt and verifier, and the stored secrets. `KeychainRekeyBackend`
/// in the app; one in memory in a test, which is the only way to rehearse an
/// interruption at every step without risking a real vault.
protocol RekeyBackend {
    /// The salt and verifier the vault opens with now.
    func vaultBlobs() -> (salt: Data, verifier: Data)?
    /// The new salt and verifier, written once everything is staged and
    /// removed once the change is complete. Their presence at launch is how
    /// an interrupted change is noticed.
    func pendingBlobs() -> (salt: Data, verifier: Data)?
    func writePending(salt: Data, verifier: Data) throws
    func deletePending()
    /// Each one a single in-place update, never a delete and an add: the salt
    /// write is the moment the change takes effect, and there must be no
    /// instant at which the vault has none.
    func updateSalt(_ salt: Data) throws
    func updateVerifier(_ verifier: Data) throws

    func secretIDs() -> [UUID]
    func payload(for id: UUID) -> Data?
    /// A secret's payload under the new key, held beside the item rather than
    /// over it until the salt has changed.
    func stage(_ payload: Data, for id: UUID) throws
    func stagedIDs() -> [UUID]
    func stagedPayload(for id: UUID) -> Data?
    /// Move a staged payload over the item's own and remove the staged copy.
    /// An item that has gone in the meantime just loses its staged copy.
    func promoteStaged(for id: UUID) throws
    func discardStaged(for id: UUID)
}

/// Changing the master passphrase: every stored secret and file re-encrypted
/// under a key derived from the new one, then the salt and verifier swapped.
///
/// The danger is being stopped part way — a crash, a power cut, a force quit —
/// with some items under the old key and some under the new, which neither
/// passphrase alone would open. So nothing is overwritten until it no longer
/// matters which key an item is under:
///
///   1. Stage. Each secret and file is opened with the old key, sealed with
///      the new, and written *beside* the original — a second Keychain item,
///      a `.next` file — then read back and opened. One that will not open
///      stops the change here, and the staged copies are thrown away.
///   2. Record the new salt and verifier as pending.
///   3. Swap the salt. This single Keychain update is the commit point:
///      before it the vault is the old one, after it the new one.
///   4. Swap the verifier, promote every staged copy over its original, and
///      remove the pending record.
///
/// `recover` runs at every launch and finishes whichever side of step 3 an
/// interrupted change was on: before it, the staged copies are discarded and
/// the old passphrase still works; after it, the promotion is completed and
/// the new one does. Neither direction needs a passphrase, because step 4
/// only moves bytes that are already sealed.
///
/// Plain-text secrets — written before the passphrase was set and never
/// encrypted — are left as they are: there is nothing to re-key, and the
/// encryption sweep is what deals with them.
enum PassphraseChange {
    enum Outcome: Equatable {
        /// Nothing was interrupted. Leftover staged copies with no pending
        /// record, from a change stopped before step 2, may have been removed.
        case nothingToDo
        /// A change stopped before the salt swap; the old passphrase stands.
        case rolledBack
        /// A change stopped after it; finished, and the new passphrase stands.
        case completed
        /// After it, but some of the finishing failed again. The new
        /// passphrase stands; items not yet promoted are still under the old
        /// key, with their new copies staged, and the next call finishes them.
        case unfinished
    }

    /// What a change hands back: the key to adopt, and whether every item is
    /// already under it. When not, the rest is finished by `recover` at the
    /// next launch, and until then those items will not open.
    struct Result {
        let key: SymmetricKey
        let finished: Bool
    }

    enum ChangeError: LocalizedError {
        case notConfigured
        case unreadableSecret(UUID)
        case unreadableFiles([String])
        case verificationFailed(UUID)

        var errorDescription: String? {
            switch self {
            case .notConfigured:
                return "There is no master passphrase to change."
            case .unreadableSecret:
                return "A stored secret could not be opened with the current passphrase, so "
                    + "nothing was changed."
            case .unreadableFiles(let names):
                return "These stored files could not be opened with the current passphrase, so "
                    + "nothing was changed:\n" + names.joined(separator: "\n")
            case .verificationFailed:
                return "A secret re-encrypted under the new passphrase did not read back the same, "
                    + "so nothing was changed."
            }
        }
    }

    private static let saltBytes = 32

    /// Re-key the vault. Returns the new key for the caller to adopt; the old
    /// passphrase is checked against the stored verifier first, so a wrong one
    /// throws `wrongPassphrase` with nothing written.
    ///
    /// Synchronous and slow — two key derivations and a Keychain write per
    /// item — so it belongs off the main thread.
    static func change(from current: String, to new: String,
                       backend: RekeyBackend, files: FileStore.Rekeying,
                       newSalt: Data? = nil) throws -> Result {
        // A change stopped earlier has to be settled first, or its staged
        // copies would be mistaken for this one's.
        _ = recover(backend: backend, files: files)

        guard let vault = backend.vaultBlobs() else { throw ChangeError.notConfigured }
        guard let oldKey = try VaultCrypto.key(for: current, salt: vault.salt,
                                               verifier: vault.verifier) else {
            throw VaultCrypto.CryptoError.wrongPassphrase
        }

        let salt = try newSalt ?? randomSalt()
        let newKey = try VaultCrypto.derive(passphrase: VaultCrypto.normalized(new), salt: salt)
        let verifier = try VaultCrypto.makeVerifier(using: newKey)

        // 1. Stage. Any failure here leaves the vault exactly as it was.
        do {
            for id in backend.secretIDs() {
                guard let payload = backend.payload(for: id) else { throw ChangeError.unreadableSecret(id) }
                guard VaultCrypto.isEncrypted(payload) else { continue }
                guard let plaintext = try? VaultCrypto.decrypt(payload, for: id, using: oldKey) else {
                    throw ChangeError.unreadableSecret(id)
                }
                try backend.stage(VaultCrypto.encrypt(plaintext, for: id, using: newKey), for: id)
                guard let check = backend.stagedPayload(for: id),
                      (try? VaultCrypto.decrypt(check, for: id, using: newKey)) == plaintext else {
                    throw ChangeError.verificationFailed(id)
                }
            }
            try files.stageAll(from: oldKey, to: newKey)
        } catch {
            discardStaged(backend: backend, files: files)
            throw error
        }

        // 2. Record what the vault is about to become.
        do {
            try backend.writePending(salt: salt, verifier: verifier)
        } catch {
            discardStaged(backend: backend, files: files)
            throw error
        }

        // 3. The commit point. A throw here does not by itself mean the salt
        // is unchanged — the update can land and its read-back fail — so
        // which way to go is decided by what the Keychain now holds, which is
        // exactly the question `recover` answers.
        do {
            try backend.updateSalt(salt)
        } catch {
            switch recover(backend: backend, files: files) {
            case .completed: return Result(key: newKey, finished: true)
            case .unfinished: return Result(key: newKey, finished: false)
            case .nothingToDo, .rolledBack: throw error
            }
        }

        // 4. Past the point of no return: from here a failure is finished by
        // `recover` at the next launch rather than undone, so it is reported
        // as unfinished, never thrown as if the change had not happened.
        return Result(key: newKey, finished: recover(backend: backend, files: files) == .completed)
    }

    /// Settle a change that was interrupted. Safe to call at any time, and a
    /// no-op when there is nothing to settle.
    @discardableResult
    static func recover(backend: RekeyBackend, files: FileStore.Rekeying) -> Outcome {
        guard let pending = backend.pendingBlobs() else {
            discardStaged(backend: backend, files: files)
            return .nothingToDo
        }
        guard let vault = backend.vaultBlobs(), vault.salt == pending.salt else {
            discardStaged(backend: backend, files: files)
            backend.deletePending()
            return .rolledBack
        }

        // The salt is the new one, so the new key is the vault's. Everything
        // below is idempotent, and stops short of removing the pending record
        // if any of it fails, so the next launch tries again.
        do {
            if vault.verifier != pending.verifier { try backend.updateVerifier(pending.verifier) }
            for id in backend.stagedIDs() { try backend.promoteStaged(for: id) }
            try files.promoteAll()
        } catch {
            return .unfinished
        }
        backend.deletePending()
        // Removing the record cannot report failure, so it is checked: left
        // in place, the next launch would only find nothing to promote and
        // try again, but "completed" should mean exactly that.
        return backend.pendingBlobs() == nil ? .completed : .unfinished
    }

    private static func discardStaged(backend: RekeyBackend, files: FileStore.Rekeying) {
        for id in backend.stagedIDs() { backend.discardStaged(for: id) }
        files.discardAll()
    }

    private static func randomSalt() throws -> Data {
        var salt = Data(count: saltBytes)
        let ok = salt.withUnsafeMutableBytes { buf in
            SecRandomCopyBytes(kSecRandomDefault, saltBytes, buf.baseAddress!) == errSecSuccess
        }
        guard ok else { throw VaultCrypto.CryptoError.keychain(errSecAllocate) }
        return salt
    }
}

/// The app's backend: the login Keychain, through the two stores that own it.
struct KeychainRekeyBackend: RekeyBackend {
    func vaultBlobs() -> (salt: Data, verifier: Data)? { VaultCrypto.vaultBlobs() }
    func pendingBlobs() -> (salt: Data, verifier: Data)? { VaultCrypto.pendingBlobs() }
    func writePending(salt: Data, verifier: Data) throws {
        try VaultCrypto.writePending(salt: salt, verifier: verifier)
    }
    func deletePending() { VaultCrypto.deletePending() }
    func updateSalt(_ salt: Data) throws { try VaultCrypto.updateSalt(salt) }
    func updateVerifier(_ verifier: Data) throws { try VaultCrypto.updateVerifier(verifier) }

    func secretIDs() -> [UUID] { SecretStore.rekeyableIDs() }
    func payload(for id: UUID) -> Data? { SecretStore.rekeyPayload(for: id) }
    func stage(_ payload: Data, for id: UUID) throws { try SecretStore.stage(payload, for: id) }
    func stagedIDs() -> [UUID] { SecretStore.stagedIDs() }
    func stagedPayload(for id: UUID) -> Data? { SecretStore.stagedPayload(for: id) }
    func promoteStaged(for id: UUID) throws { try SecretStore.promoteStaged(for: id) }
    func discardStaged(for id: UUID) { SecretStore.discardStaged(for: id) }
}
