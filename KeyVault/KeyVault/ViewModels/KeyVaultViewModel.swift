import Foundation
import AppKit

@Observable
@MainActor
final class KeyVaultViewModel {
    var allKeys: [EncryptionKey] = []
    var selectedType: KeyType? = nil
    var selectedKeyID: UUID? = nil
    var isLoading = false
    var showGenerateSheet = false
    var showImportSheet = false
    var showAddAPIKeySheet = false
    var showAddNoteSheet = false
    var showBackupSheet = false
    var showSettings = false
    var settings: AppSettings
    var errorMessage: String? = nil

    private let shell = ShellService()
    private let exportService = VaultExportService()
    private let sshService = SSHService()
    private let gpgService = GPGService()
    private let ageService = AgeService()

    init() {
        self.settings = AppSettings.load()
    }

    var filteredKeys: [EncryptionKey] {
        guard let type = selectedType else { return allKeys }
        return allKeys.filter { $0.type == type }
    }

    var selectedKey: EncryptionKey? {
        allKeys.first { $0.id == selectedKeyID }
    }

    func keyCount(for type: KeyType) -> Int {
        allKeys.filter { $0.type == type }.count
    }

    func reload() async {
        isLoading = true
        errorMessage = nil

        async let sshKeys = loadSSH()
        async let gpgKeys = loadGPG()
        async let ageKeys = loadAge()
        let stored = SecretStore.loadAll()

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
        case .note:
            // Notes have no public half. The secret itself is copied from the
            // detail view, deliberately never from a list action.
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
            if let path = key.path {
                try FileManager.default.removeItem(atPath: path)
                let pubPath = path + ".pub"
                try? FileManager.default.removeItem(atPath: pubPath)
            }
        case .gpg:
            if let keyID = key.keyID {
                try await gpgService.deleteKey(keyID, includeSecret: key.hasPrivateKey)
            }
        case .age:
            break // Age key deletion not supported — managed via key files
        case .api:
            try SecretStore.delete(id: key.id)
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

    func generateGPGKey(name: String, email: String, algorithm: String, expiry: String) async throws {
        try await gpgService.generate(name: name, email: email, algorithm: algorithm, expiry: expiry)
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

    func addNote(name: String, secret: String, notes: String?) async {
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
        } catch {
            await appendError("Note: \(error.localizedDescription)")
        }
    }

    /// Replace every stored-secret row in one go. Removing by a single type
    /// and re-appending the whole store duplicated the other one — the store
    /// owns more than API keys now, so the removal has to own the same set.
    private func refreshStoredSecrets() {
        allKeys.removeAll { SecretStore.ownedTypes.contains($0.type) }
        allKeys.append(contentsOf: SecretStore.loadAll())
    }

    // MARK: - Backup

    func exportVault(passphrase: String) async throws -> String {
        try await exportService.exportArchive(passphrase: passphrase)
    }

    func importVault(armored: String, passphrase: String) async throws -> (added: Int, updated: Int) {
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
