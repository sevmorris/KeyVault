import Foundation

/// Passphrase-encrypted export and import of everything `SecretStore` owns.
///
/// Uses GnuPG symmetric encryption rather than the `age` wrapper this app also
/// carries, for three reasons: `age` is not installed (`AgeService` would throw
/// `toolNotFound` today) while `gnupg` is, and is in the machine's Brewfile;
/// `age` cannot take a passphrase non-interactively, which a GUI app has no way
/// to supply; and a passphrase means one thing to remember rather than an
/// identity file that becomes a second irreplaceable secret needing its own
/// backup — the regress this feature exists to end.
///
/// Output is ASCII-armored on purpose. The archive is text: it survives being
/// pasted into a password manager, mailed to yourself, or printed, none of
/// which a binary blob does reliably.
actor VaultExportService {
    private let shell = ShellService()

    private func gpgPath() throws -> String {
        try GPGLocator.resolve()
    }

    // MARK: - Export

    /// Encrypt every owned secret to an armored OpenPGP document.
    func exportArchive(passphrase: String) async throws -> String {
        guard !passphrase.isEmpty else {
            throw KeyError.exportFailed("A passphrase is required.")
        }

        let keys = SecretStore.loadAll()
        guard !keys.isEmpty else {
            throw KeyError.exportFailed("There is nothing to export yet.")
        }

        var items: [VaultArchive.Item] = []
        for key in keys {
            // A single unreadable item must fail the whole export. A backup
            // that silently omits one secret is worse than no backup, because
            // you will not discover the gap until you need that secret.
            let secret = try SecretStore.loadSecret(for: key.id)
            items.append(
                VaultArchive.Item(
                    id: key.id,
                    type: key.type.rawValue,
                    name: key.name,
                    service: key.service,
                    notes: key.notes,
                    createdDate: key.createdDate,
                    secret: secret
                )
            )
        }

        let archive = VaultArchive(exportedAt: Date(), items: items)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let plaintext = try encoder.encode(archive)

        return try await encrypt(plaintext, passphrase: passphrase)
    }

    private func encrypt(_ plaintext: Data, passphrase: String) async throws -> String {
        let gpg = try gpgPath()
        let passFile = try writeTemporaryPassphraseFile(passphrase)
        defer { try? FileManager.default.removeItem(at: passFile.dir) }

        // The vault contents go over stdin and never touch the disk in the
        // clear. Only the passphrase is written to a file, in a 0700 directory
        // at 0600, and removed on the way out — the lesser of the two evils
        // that gpg's single-stdin constraint forces, since the alternative is
        // spilling every secret to a temp file instead.
        let result = try await shell.runWithStdin(
            gpg,
            arguments: [
                "--batch", "--yes", "--quiet",
                "--pinentry-mode", "loopback",
                "--passphrase-file", passFile.file.path,
                "--symmetric", "--cipher-algo", "AES256",
                "--armor", "--output", "-"
            ],
            stdinData: plaintext
        )

        guard result.status == 0, !result.stdout.isEmpty else {
            throw KeyError.exportFailed(result.stderr.isEmpty ? "gpg failed" : result.stderr)
        }
        return result.stdout
    }

    // MARK: - Import

    /// Decrypt and parse an archive. Returns its items without writing
    /// anything — deciding what to do with a collision is the caller's job.
    func readArchive(armored: String, passphrase: String) async throws -> VaultArchive {
        let gpg = try gpgPath()
        guard let ciphertext = armored.data(using: .utf8) else {
            throw KeyError.exportFailed("Archive is not valid text.")
        }
        let passFile = try writeTemporaryPassphraseFile(passphrase)
        defer { try? FileManager.default.removeItem(at: passFile.dir) }

        let result = try await shell.runWithStdin(
            gpg,
            arguments: [
                "--batch", "--yes", "--quiet",
                "--pinentry-mode", "loopback",
                "--passphrase-file", passFile.file.path,
                "--decrypt"
            ],
            stdinData: ciphertext
        )

        guard result.status == 0, let data = result.stdout.data(using: .utf8) else {
            throw KeyError.exportFailed(
                result.stderr.contains("Bad session key") || result.stderr.contains("decryption failed")
                    ? "Wrong passphrase."
                    : (result.stderr.isEmpty ? "gpg failed" : result.stderr)
            )
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let archive = try decoder.decode(VaultArchive.self, from: data)

        guard archive.formatVersion <= VaultArchive.currentFormatVersion else {
            throw KeyError.exportFailed(
                "This archive was written by a newer version of KeyVault "
                + "(format \(archive.formatVersion)). Update before importing."
            )
        }
        return archive
    }

    /// Write an archive's items into the store. Existing ids are updated rather
    /// than duplicated, so re-importing the same archive is idempotent — which
    /// is what makes a restore drill safe to rehearse.
    ///
    /// Anything this build does not recognise is counted and reported rather
    /// than dropped quietly. The export half of this file refuses to omit a
    /// single secret on the grounds that a backup with a silent gap is worse
    /// than none; a restore that silently declines to write one is the same
    /// bargain, and the user is equally entitled to hear about it.
    func restore(_ archive: VaultArchive) throws -> (added: Int, updated: Int, skipped: Int) {
        let existing = Set(SecretStore.loadAll().map(\.id))
        var added = 0
        var updated = 0
        var skipped = 0

        for item in archive.items {
            guard let type = KeyType(rawValue: item.type), SecretStore.ownedTypes.contains(type) else {
                skipped += 1
                continue
            }
            let key = EncryptionKey(
                id: item.id,
                type: type,
                name: item.name,
                service: item.service,
                notes: item.notes,
                createdDate: item.createdDate,
                hasPrivateKey: false
            )
            if existing.contains(item.id) {
                try SecretStore.update(key, newSecret: item.secret)
                updated += 1
            } else {
                try SecretStore.save(key, secret: item.secret)
                added += 1
            }
        }
        return (added, updated, skipped)
    }

    // MARK: - Helpers

    private func writeTemporaryPassphraseFile(_ passphrase: String) throws -> (dir: URL, file: URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("keyvault-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let file = dir.appendingPathComponent("pass")
        guard let data = passphrase.data(using: .utf8) else {
            throw KeyError.exportFailed("Passphrase is not valid text.")
        }
        try data.write(to: file, options: .completeFileProtection)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        return (dir, file)
    }
}
