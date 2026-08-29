import SwiftUI
import UniformTypeIdentifiers

/// Export and restore the encrypted archive.
///
/// Both halves live in one view deliberately. An export UI without a visible
/// restore beside it encourages the failure this feature exists to prevent:
/// backups taken faithfully for years and never once read back. Restore is not
/// the emergency path, it is the rehearsal, and it should be as easy to find as
/// the thing it verifies.
struct BackupView: View {
    let viewModel: KeyVaultViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var passphrase = ""
    @State private var confirmation = ""
    @State private var isWorking = false
    @State private var status: String?
    @State private var errorMessage: String?
    @State private var isImporting = false

    private var canExport: Bool {
        !passphrase.isEmpty && passphrase == confirmation && !isWorking
    }
    private var canRestore: Bool {
        !passphrase.isEmpty && !isWorking
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Backup")
                .font(.headline)
                .padding([.top, .horizontal])

            Form {
                Section {
                    SecureField("Passphrase", text: $passphrase)
                    SecureField("Confirm (export only)", text: $confirmation)
                } header: {
                    Text("Passphrase")
                } footer: {
                    // The one warning that matters: this passphrase is not
                    // stored anywhere, by design, and there is no reset.
                    Text("Nothing stores this passphrase. If you lose it the archive is unreadable — by you as well as by anyone else.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section {
                    Button("Export Encrypted Archive…") { export() }
                        .disabled(!canExport)
                    Button("Restore from Archive…") { isImporting = true }
                        .disabled(!canRestore)
                } footer: {
                    Text("""
                        The archive is OpenPGP (AES-256) and armored, so it is plain text and any \
                        gpg can read it without KeyVault:  gpg --decrypt keyvault-export.asc

                        Restore adds what is missing and updates what already exists, so importing \
                        the same archive twice is harmless — rehearse it.
                        """)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)

            if let status {
                Text(status).font(.caption).foregroundStyle(.green).padding(.horizontal)
            }
            if let errorMessage {
                Text(errorMessage).font(.caption).foregroundStyle(.red).padding(.horizontal)
            }

            HStack {
                if isWorking { ProgressView().controlSize(.small) }
                Spacer()
                // Escape, not Return. As the default action this button
                // swallowed the Return keypress that ends typing a passphrase,
                // closing the sheet instead of exporting anything.
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
            }
            .padding()
        }
        .frame(width: 480, height: 460)
        .fileImporter(
            isPresented: $isImporting,
            allowedContentTypes: [.plainText, .data],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first { restore(from: url) }
        }
    }

    private func export() {
        isWorking = true; status = nil; errorMessage = nil
        Task {
            do {
                let armored = try await viewModel.exportVault(passphrase: passphrase)
                if let url = presentSavePanel() {
                    try armored.write(to: url, atomically: true, encoding: .utf8)
                    status = "Exported to \(url.lastPathComponent). Restore it somewhere else before trusting it."
                }
            } catch {
                errorMessage = error.localizedDescription
            }
            isWorking = false
        }
    }

    private func restore(from url: URL) {
        isWorking = true; status = nil; errorMessage = nil
        Task {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            do {
                let armored = try String(contentsOf: url, encoding: .utf8)
                let counts = try await viewModel.importVault(armored: armored, passphrase: passphrase)
                var summary = "Restored: \(counts.added) added, \(counts.updated) updated."
                if counts.skipped > 0 {
                    // Named, not buried: an item this build cannot store is
                    // still in the archive, and the archive is still the copy
                    // that has it.
                    summary += " \(counts.skipped) item\(counts.skipped == 1 ? "" : "s") "
                        + "skipped — this version of KeyVault does not recognise "
                        + "their type. Keep this archive."
                }
                status = summary
            } catch {
                errorMessage = error.localizedDescription
            }
            isWorking = false
        }
    }

    @MainActor
    private func presentSavePanel() -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "keyvault-export.asc"
        // No allowedContentTypes: constraining to .plainText makes the panel
        // enforce that type's extension and save "keyvault-export.asc.txt".
        // .asc has no registered UTType to name instead, so the right move is
        // to stop constraining and let the filename stand.
        panel.allowsOtherFileTypes = true
        panel.canCreateDirectories = true
        panel.message = "Save the encrypted archive somewhere that is not this Mac."
        return panel.runModal() == .OK ? panel.url : nil
    }
}
