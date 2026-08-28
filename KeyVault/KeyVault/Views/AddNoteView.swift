import SwiftUI
import UniformTypeIdentifiers

/// Entry for a secret KeyVault owns outright.
///
/// Separate from `AddAPIKeyView` because the two ask different questions. An
/// API key has a service it belongs to and fits on one line; a note is a
/// recovery sheet, a set of codes, a key file's contents — multi-line by
/// nature, and belonging to nothing.
///
/// The editor is a plain `TextEditor`, not a `SecureField`. Masking is the
/// wrong trade here: these are pasted in bulk, often from a file, and a
/// single-line masked field silently mangles multi-line input while hiding the
/// evidence that it did. You cannot proof-read what you cannot see, and for a
/// value nothing else holds a copy of, proof-reading is the point.
struct AddNoteView: View {
    let viewModel: KeyVaultViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var secret = ""
    @State private var notes = ""
    @State private var isImporting = false
    @State private var importError: String?
    @State private var isSaving = false

    private var isValid: Bool {
        !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !secret.isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Add Note")
                .font(.headline)
                .padding([.top, .horizontal])

            Form {
                TextField("Name", text: $name, prompt: Text("e.g. GitHub recovery codes"))

                Section {
                    TextEditor(text: $secret)
                        .font(.system(.body, design: .monospaced))
                        .frame(minHeight: 160)
                        .border(Color.secondary.opacity(0.3))
                } header: {
                    HStack {
                        Text("Secret")
                        Spacer()
                        Button("Load from File…") { isImporting = true }
                            .font(.caption)
                    }
                } footer: {
                    // Says the quiet part: this is the only copy once it is in.
                    Text("Stored in the Keychain. Export an encrypted backup before this is the only copy.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                TextField("Notes", text: $notes, axis: .vertical)
                    .lineLimit(2...4)
            }
            .formStyle(.grouped)

            if let importError {
                Text(importError)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .padding(.horizontal)
            }

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!isValid || isSaving)
            }
            .padding()
        }
        .frame(width: 460, height: 480)
        .fileImporter(
            isPresented: $isImporting,
            allowedContentTypes: [.plainText, .json, .data],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
                loadFile(url)
            case .failure(let error):
                importError = error.localizedDescription
            }
        }
    }

    /// Read a file verbatim. No trimming: a trailing newline is part of some
    /// key formats, and "helpfully" stripping it produces a value that looks
    /// right and does not work.
    private func loadFile(_ url: URL) {
        importError = nil
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        do {
            let data = try Data(contentsOf: url)
            guard let text = String(data: data, encoding: .utf8) else {
                importError = "That file isn't UTF-8 text. Notes hold text; binary files aren't supported."
                return
            }
            secret = text
            if name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                name = url.lastPathComponent
            }
        } catch {
            importError = error.localizedDescription
        }
    }

    private func save() {
        isSaving = true
        Task {
            await viewModel.addNote(
                name: name.trimmingCharacters(in: .whitespacesAndNewlines),
                secret: secret,
                notes: notes.isEmpty ? nil : notes
            )
            isSaving = false
            dismiss()
        }
    }
}
