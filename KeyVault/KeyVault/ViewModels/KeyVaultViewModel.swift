import Foundation
import AppKit

@Observable
@MainActor
final class KeyVaultViewModel {
    var allKeys: [EncryptionKey] = []
    /// Opens on notes rather than on everything. The key types are an
    /// inventory of things other tools own; the stored secrets are what this
    /// app is for, and a flat list of all five buried them.
    var selectedType: KeyType? = .note
    var selectedKeyID: UUID? = nil
    var isLoading = false
    var showGenerateSheet = false
    var showImportSheet = false
    var showAddAPIKeySheet = false
    var showAddNoteSheet = false
    var showAddFileSheet = false
    /// A file dropped on the list, for the Add File sheet the drop opens.
    var droppedFileURL: URL?
    var showBackupSheet = false
    var showSettings = false

    // MARK: - Vault lock
    //
    // Mirrored into stored properties rather than read through computed ones:
    // VaultCrypto's state lives outside the observation system, so a computed
    // property would not re-render the gate when it changes.
    var isVaultConfigured = VaultCrypto.isConfigured
    var isVaultUnlocked = VaultCrypto.isUnlocked
    /// Whether the vault was shut by the idle timer rather than properly
    /// locked — the one state a fingerprint can reopen.
    var isVaultSuspended = VaultCrypto.isSuspended
    /// Refreshed alongside the lock state rather than read from a view body:
    /// this puts a real question to LocalAuthentication, and a body can run
    /// many times over. Every transition that can show the locked screen goes
    /// through `refreshVaultState()`, so it is current when it is read.
    var isBiometricsAvailable = false
    var showVaultSetup = false
    /// Whether the passphrase prompt is on screen. Raised at launch when the
    /// vault is locked, but it is a door you are allowed to walk away from:
    /// cancelling leaves the window open and locked rather than holding you
    /// there until you produce the passphrase or force-quit.
    var showVaultUnlock = false
    /// Set after first-time setup so the caller can offer the sweep at the one
    /// moment the user is already thinking about it.
    var offerEncryptExisting = false
    /// Set when that first-time setup happened inside the Add File sheet. An
    /// alert cannot appear over the sheet, so the offer waits for it to close.
    var offerEncryptWhenAddFileCloses = false

    /// The whole app sits behind this. Gating once at the door beats scattering
    /// lock checks through every read: if you are looking at the list, the vault
    /// is open, and export, reveal and edit all just work.
    var vaultIsLocked: Bool { isVaultConfigured && !isVaultUnlocked }

    func refreshVaultState() {
        isVaultConfigured = VaultCrypto.isConfigured
        isVaultUnlocked = VaultCrypto.isUnlocked
        isVaultSuspended = VaultCrypto.isSuspended
        isBiometricsAvailable = BiometricAuth.isAvailable
    }

    func lockVault() {
        VaultCrypto.lock()
        refreshVaultState()
        clearLoadedSecrets()
    }

    /// The idle lock. The screen clears exactly as it does for a real lock —
    /// what differs is that the key is set aside rather than forgotten, so
    /// Touch ID can put it back. See `VaultCrypto.suspend()`.
    func idleLockVault() {
        guard !vaultIsLocked else { return }
        VaultCrypto.suspend()
        refreshVaultState()
        clearLoadedSecrets()
    }

    /// Bring back a vault the idle timer shut. Answers false without comment
    /// when there is nothing to resume, which is every case except that one.
    @discardableResult
    func resumeWithBiometrics() async -> Bool {
        guard VaultCrypto.isSuspended else { return false }
        switch await BiometricAuth.authenticate(reason: "unlock your vault") {
        case .success:
            VaultCrypto.resume()
            vaultDidUnlock()
            await reload()
            return true
        case .cancelled:
            return false
        case .failed(let message):
            await appendError(message)
            return false
        }
    }

    /// Shutting the door has to empty the room as well. The rows carry names,
    /// services and categories in the clear, and leaving them in memory behind
    /// a locked screen is most of what locking was for.
    private func clearLoadedSecrets() {
        allKeys.removeAll { $0.type.isStored }
        selectedKeyID = nil
    }

    /// Whether the locked screen should offer a fingerprint. Both halves
    /// matter: a vault that was properly locked cannot be reopened this way at
    /// all, and a Mac with no enrolled finger must not advertise it.
    var canResumeWithBiometrics: Bool {
        isVaultSuspended && isBiometricsAvailable
    }

    /// Encrypt whatever is still stored as plaintext. Reports what it did
    /// rather than claiming success: a sweep in this app has already once
    /// recorded a clean pass while protecting nothing.
    func encryptExistingSecrets() async {
        do {
            let result = try SecretStore.encryptExistingSecrets()
            if result.failed > 0 {
                await appendError("Encrypted \(result.encrypted). \(result.failed) could not be encrypted and are still stored as plain text.")
            } else if result.encrypted > 0 {
                await appendError("Encrypted \(result.encrypted) secret(s).")
            } else {
                await appendError("Everything was already encrypted.")
            }
            await reload()
        } catch {
            await appendError(error.localizedDescription)
        }
    }
    var settings: AppSettings
    var errorMessage: String? = nil

    private let idleWatcher = IdleWatcher()
    private let exportService = VaultExportService()
    private let fileStore = FileStore.standard
    private let sshService = SSHService()
    private let gpgService = GPGService()
    private let ageService = AgeService()

    init() {
        self.settings = AppSettings.load()
        self.collapsedCategories = Set(
            UserDefaults.standard.stringArray(forKey: Self.collapsedCategoriesKey) ?? []
        )
        // Asked for once, at launch, rather than presented by a binding that
        // re-raises it the instant it is dismissed.
        self.showVaultUnlock = VaultCrypto.isConfigured && !VaultCrypto.isUnlocked

        idleWatcher.idleLimit = { [weak self] in
            guard let self, settings.idleLockMinutes > 0 else { return nil }
            return TimeInterval(settings.idleLockMinutes * 60)
        }
        idleWatcher.onIdle = { [weak self] in self?.idleLockVault() }
        idleWatcher.start()
    }

    var filteredKeys: [EncryptionKey] {
        guard let type = selectedType else { return allKeys }
        return allKeys.filter { $0.type == type }
    }

    var selectedKey: EncryptionKey? {
        allKeys.first { $0.id == selectedKeyID }
    }

    // MARK: - Note categories

    struct NoteGroup {
        let name: String
        let keys: [EncryptionKey]
    }

    /// Uncategorised notes sort last under their own heading rather than being
    /// hidden or lumped into the first real category.
    static let uncategorisedLabel = "Uncategorised"

    var hasAnyCategory: Bool {
        filteredKeys.contains { $0.category?.isEmpty == false }
    }

    var groupedNotes: [NoteGroup] {
        let buckets = Dictionary(grouping: filteredKeys) { key -> String in
            let c = key.category?.trimmingCharacters(in: .whitespaces) ?? ""
            return c.isEmpty ? Self.uncategorisedLabel : c
        }
        return buckets
            .map { NoteGroup(name: $0.key, keys: $0.value.sorted {
                $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
            }) }
            .sorted { a, b in
                if a.name == Self.uncategorisedLabel { return false }
                if b.name == Self.uncategorisedLabel { return true }
                return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
            }
    }

    // MARK: - Category collapse

    /// Collapsed, not expanded, is what gets remembered: a category the user
    /// has never touched should be open, and so should one that appears later
    /// because a note was filed under a new name.
    private static let collapsedCategoriesKey = "CollapsedNoteCategories"
    private var collapsedCategories: Set<String>

    func isCategoryExpanded(_ name: String) -> Bool {
        !collapsedCategories.contains(name)
    }

    func toggleCategory(_ name: String) {
        if collapsedCategories.contains(name) {
            collapsedCategories.remove(name)
        } else {
            collapsedCategories.insert(name)
        }
        // Survives a relaunch. Sorted so the stored array does not churn on
        // every toggle just because a Set has no order.
        UserDefaults.standard.set(collapsedCategories.sorted(),
                                  forKey: Self.collapsedCategoriesKey)
    }

    var showBulkCategorise = false

    /// Write the categories chosen in the bulk screen.
    ///
    /// Only notes whose category actually changed are written: each write is a
    /// Keychain update, and re-writing 24 items to change three is both slower
    /// and more chances to fail for no reason.
    func applyCategories(_ assignments: [UUID: String]) async {
        var failures: [String] = []
        for var note in allKeys where note.type == .note {
            let wanted = (assignments[note.id] ?? "").trimmingCharacters(in: .whitespaces)
            let current = (note.category ?? "").trimmingCharacters(in: .whitespaces)
            guard wanted != current else { continue }
            note.category = wanted.isEmpty ? nil : wanted
            do {
                // Metadata only — passing nil leaves the stored secret alone, so
                // filing a note never risks the thing the note exists to hold.
                try SecretStore.update(note, newSecret: nil)
            } catch {
                failures.append("\(note.name): \(error.localizedDescription)")
            }
        }
        // Reported after the reload, not before it. reload() starts by
        // clearing errorMessage, which is where a note that failed to file
        // used to be reported — so the failure went unseen, the sheet closed
        // as if it had all worked, and the note kept its old category.
        await reload()
        forgetCollapsedCategoriesNotInUse()
        if !failures.isEmpty {
            await appendError("Could not file:\n" + failures.joined(separator: "\n"))
        }
    }

    /// A category that no note is filed under any more — renamed or removed —
    /// is dropped from the collapsed set, so that one made again later under
    /// the same name does not come back already folded away.
    private func forgetCollapsedCategoriesNotInUse() {
        let inUse = Set(allKeys.compactMap { key -> String? in
            guard key.type == .note, let c = key.category?.trimmingCharacters(in: .whitespaces),
                  !c.isEmpty else { return nil }
            return c
        })
        let kept = collapsedCategories.intersection(inUse)
        guard kept != collapsedCategories else { return }
        collapsedCategories = kept
        UserDefaults.standard.set(collapsedCategories.sorted(), forKey: Self.collapsedCategoriesKey)
    }

    func keyCount(for type: KeyType) -> Int {
        allKeys.filter { $0.type == type }.count
    }

    /// Called after any successful unlock, so a vault just opened is not
    /// measured against however long it sat closed.
    func vaultDidUnlock() {
        refreshVaultState()
        idleWatcher.reset()
    }

    func reload() async {
        isLoading = true
        errorMessage = nil

        async let sshKeys = loadSSH()
        async let gpgKeys = loadGPG()
        async let ageKeys = loadAge()
        // Nothing stored is read while the vault is locked. The metadata would
        // load — only the payload is ciphertext — so this is the difference
        // between a locked vault and one that lists everything in it by name.
        var stored: [EncryptionKey] = []
        if !vaultIsLocked {
            stored = SecretStore.loadAll() + (await loadFiles())
        }

        let (ssh, gpg, age) = await (sshKeys, gpgKeys, ageKeys)
        allKeys = ssh + gpg + age + stored
        isLoading = false
    }

    private func loadSSH() async -> [EncryptionKey] {
        do {
            return try await sshService.loadKeys()
        } catch {
            await appendError("SSH: \(error.localizedDescription)")
            return []
        }
    }

    private func loadGPG() async -> [EncryptionKey] {
        do {
            return try await gpgService.loadKeys()
        } catch {
            // GPG not installed is common and not an error worth surfacing
            return []
        }
    }

    /// Stored files, with any that will not open named rather than dropped. A
    /// file missing from this list is missing from the backup too, which is
    /// why the export refuses outright in the same situation.
    private func loadFiles() async -> [EncryptionKey] {
        let listing = fileStore.loadAll()
        if !listing.unreadable.isEmpty {
            await appendError("Files that could not be read:\n"
                              + listing.unreadable.joined(separator: "\n"))
        }
        return listing.files
    }

    private func loadAge() async -> [EncryptionKey] {
        do {
            return try await ageService.loadKeys(from: settings.ageKeyPaths)
        } catch {
            await appendError("Age: \(error.localizedDescription)")
            return []
        }
    }

    private func appendError(_ message: String) async {
        if let existing = errorMessage {
            errorMessage = existing + "\n" + message
        } else {
            errorMessage = message
        }
    }

    func copyPublicKey(_ key: EncryptionKey) {
        let text: String
        switch key.type {
        case .note, .file:
            // Notes and files have no public half. What they hold is copied or
            // saved from the detail view, deliberately never from a list action.
            return
        case .ssh:
            text = key.publicKey ?? ""
        case .gpg:
            Task {
                do {
                    guard let keyID = key.keyID else { return }
                    let armored = try await gpgService.exportPublicKey(keyID)
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(armored, forType: .string)
                } catch {
                    errorMessage = error.localizedDescription
                }
            }
            return
        case .age:
            text = key.publicKey ?? ""
        case .api:
            return // Never copy API secrets
        }
        guard !text.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    func copyFingerprint(_ key: EncryptionKey) {
        guard let fingerprint = key.fingerprint ?? key.keyID else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(fingerprint, forType: .string)
    }

    func deleteKey(_ key: EncryptionKey) async throws {
        switch key.type {
        case .note:
            try SecretStore.delete(id: key.id)
        case .ssh:
            // An entry can exist on the strength of its .pub alone, and the
            // private half is then simply not there. Removing the missing file
            // used to throw, so those rows could never be deleted at all.
            if let path = key.path {
                let fm = FileManager.default
                let pubPath = path + ".pub"
                var removed = false
                for candidate in [path, pubPath] where fm.fileExists(atPath: candidate) {
                    try fm.removeItem(atPath: candidate)
                    removed = true
                }
                guard removed else {
                    throw KeyError.deleteFailed(
                        "Neither \(path) nor \(pubPath) is on disk any more."
                    )
                }
            }
        case .gpg:
            // The fingerprint, not the key id — see GPGService.deleteKey. A key
            // with neither recorded is not something to guess at, so say so
            // rather than silently succeed at having done nothing, which is
            // what the previous `if let` did.
            guard let fingerprint = key.fingerprint else {
                throw KeyError.deleteFailed(
                    "No fingerprint was recorded for this key, and gpg will not "
                    + "delete one without it. Remove it with: gpg --delete-secret-and-public-key"
                )
            }
            try await gpgService.deleteKey(fingerprint: fingerprint, includeSecret: key.hasPrivateKey)
        case .age:
            // Deleting one identity out of a shared key file is a text edit,
            // not a file removal, and guessing at it risks taking the rest of
            // the file with it. Say so rather than run the destructive
            // confirmation and then quietly do nothing.
            throw KeyError.deleteFailed(
                "Age keys live in a key file that may hold others. "
                + "Remove this identity from \(key.path ?? "the key file") by hand."
            )
        case .api:
            try SecretStore.delete(id: key.id)
        case .file:
            try fileStore.delete(id: key.id)
        }
        await reload()
    }

    func generateSSHKey(
        algorithm: String,
        bits: Int?,
        comment: String,
        path: String,
        passphrase: String
    ) async throws {
        try await sshService.generate(
            algorithm: algorithm,
            bits: bits,
            comment: comment,
            path: path,
            passphrase: passphrase
        )
        await reload()
    }

    func generateGPGKey(
        name: String,
        email: String,
        algorithm: String,
        expiry: String,
        passphrase: String
    ) async throws {
        try await gpgService.generate(
            name: name,
            email: email,
            algorithm: algorithm,
            expiry: expiry,
            passphrase: passphrase
        )
        await reload()
    }

    func generateAgeKey(outputPath: String) async throws {
        try await ageService.generate(outputPath: outputPath)
        await reload()
    }

    func addAPIKey(key: EncryptionKey, secret: String) throws {
        try SecretStore.save(key, secret: secret)
        refreshStoredSecrets()
    }

    /// Reports whether the write landed. The editor keeps what was typed when
    /// this is false: a note is the one type nothing else holds a copy of, so
    /// closing the sheet over a failed save discards the only copy there is.
    @discardableResult
    func addNote(name: String, secret: String, notes: String?) async -> Bool {
        let key = EncryptionKey(
            type: .note,
            name: name,
            notes: notes,
            createdDate: Date(),
            hasPrivateKey: false
        )
        do {
            try SecretStore.save(key, secret: secret)
            refreshStoredSecrets()
            return true
        } catch {
            await appendError("Note: \(error.localizedDescription)")
            return false
        }
    }

    /// Edit a stored note in place.
    ///
    /// The id is carried over rather than minted fresh, which is what makes an
    /// edit an edit: the Keychain item is updated, the row keeps its identity,
    /// and the selection survives a rename instead of the detail pane going
    /// blank. `createdDate` rides along on the copy so the original stays the
    /// creation date rather than becoming the last-edited date.
    @discardableResult
    func updateNote(_ key: EncryptionKey, name: String, secret: String, notes: String?) async -> Bool {
        var edited = key
        edited.name = name
        edited.notes = notes
        do {
            try SecretStore.update(edited, newSecret: secret)
            refreshStoredSecrets()
            return true
        } catch {
            await appendError("Note: \(error.localizedDescription)")
            return false
        }
    }

    /// Store a file, and then — only once it has been stored and read back —
    /// move the original to the Trash if asked to.
    ///
    /// Throws when the file could not be stored, so the sheet can say why and
    /// stay open. The Trash is the one step that can fail after the file is
    /// safely kept; that is reported rather than thrown, because the thing
    /// that matters succeeded, and the user needs to hear that the original is
    /// still sitting there unencrypted.
    func addFile(from url: URL, name: String, notes: String?, trashOriginal: Bool) async throws {
        // A symlink's target is the file. Trashing the link would leave the
        // original where it was, while reporting that it had gone.
        let original = url.resolvingSymlinksInPath()
        let scoped = original.startAccessingSecurityScopedResource()
        defer { if scoped { original.stopAccessingSecurityScopedResource() } }

        let contents = try FileStore.contentsForStoring(original)
        let key = EncryptionKey(
            type: .file,
            name: name,
            notes: notes,
            createdDate: Date(),
            fileName: original.lastPathComponent,
            fileSize: contents.count,
            hasPrivateKey: false
        )
        try fileStore.save(key, contents: contents)
        refreshStoredSecrets()

        guard trashOriginal else { return }
        do {
            try FileManager.default.trashItem(at: original, resultingItemURL: nil)
        } catch {
            await appendError("\(original.lastPathComponent) is stored, but the original could "
                              + "not be moved to the Trash: \(error.localizedDescription) It is "
                              + "still on disk, unencrypted.")
        }
    }

    /// Rename a stored file, or change its notes. The contents are untouched.
    func updateFile(_ key: EncryptionKey, name: String, notes: String?) throws {
        var edited = key
        edited.name = name
        edited.notes = notes
        try fileStore.update(edited)
        refreshStoredSecrets()
    }

    /// Replace every stored row in one go. Removing by a single type and
    /// re-appending the whole store duplicated the others — the app stores
    /// more than API keys now, so the removal has to own the same set.
    private func refreshStoredSecrets() {
        allKeys.removeAll { $0.type.isStored }
        allKeys.append(contentsOf: SecretStore.loadAll() + fileStore.loadAll().files)
    }

    // MARK: - Backup

    func exportVault(passphrase: String) async throws -> String {
        try await exportService.exportArchive(passphrase: passphrase)
    }

    func importVault(armored: String, passphrase: String) async throws -> (added: Int, updated: Int, skipped: Int) {
        let archive = try await exportService.readArchive(armored: armored, passphrase: passphrase)
        let counts = try await exportService.restore(archive)
        refreshStoredSecrets()
        return counts
    }

    func importKey(from url: URL) async throws {
        let ext = url.pathExtension.lowercased()
        let path = url.path

        if ext == "pub" {
            // SSH public key — just show it; actual SSH keys are scanned from ~/.ssh/
            // Offer to copy to ~/.ssh/
            let fm = FileManager.default
            let sshDir = NSHomeDirectory() + "/.ssh"
            let dest = sshDir + "/" + url.lastPathComponent
            if !fm.fileExists(atPath: sshDir) {
                try fm.createDirectory(atPath: sshDir, withIntermediateDirectories: true)
            }
            try fm.copyItem(atPath: path, toPath: dest)
        } else {
            // Try GPG import (armored key file)
            try await gpgService.importKey(from: path)
        }
        await reload()
    }

    func saveSettings() {
        settings.save()
    }
}
