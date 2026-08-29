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

    /// The note being edited, or nil when adding a new one. The same form
    /// serves both: an edit asks exactly the questions an add does, and a
    /// second near-identical view would be two places to fix every bug.
    var editing: EncryptionKey? = nil

    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var secret = ""
    @State private var notes = ""
    @State private var isImporting = false
    @State private var importError: String?
    @State private var isSaving = false

    /// Set when an existing note's secret could not be read back. Save stays
    /// disabled while it is non-nil: writing the empty editor over a note
    /// whose ciphertext is merely unreadable right now would turn a temporary
    /// Keychain failure into the permanent loss of the only copy.
    @State private var loadError: String?
    @State private var didLoad = false

    private var isEditing: Bool { editing != nil }

    private var isValid: Bool {
        !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !secret.isEmpty
            && loadError == nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(isEditing ? "Edit Note" : "Add Note")
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

            if let loadError {
                Text(loadError)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .padding(.horizontal)
            }

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
        .task { loadExistingNote() }
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

    /// Fill the form from the note being edited. Runs once: `.task` fires
    /// again if the view is reidentified, and re-reading would throw away
    /// edits already typed into the fields.
    private func loadExistingNote() {
        guard let editing, !didLoad else { return }
        didLoad = true
        name = editing.name
        notes = editing.notes ?? ""
        do {
            secret = try SecretStore.loadSecret(for: editing.id)
        } catch {
            loadError = "Could not read this note from the Keychain: "
                + "\(error.localizedDescription) — close and try again rather "
                + "than saving, which would overwrite it."
        }
    }

    private func save() {
        isSaving = true
        Task {
            let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
            let trimmedNotes = notes.isEmpty ? nil : notes
            let saved: Bool
            if let editing {
                saved = await viewModel.updateNote(
                    editing,
                    name: trimmedName,
                    secret: secret,
                    notes: trimmedNotes
                )
            } else {
                saved = await viewModel.addNote(
                    name: trimmedName,
                    secret: secret,
                    notes: trimmedNotes
                )
            }
            isSaving = false
            // Only on success. A dismissed sheet takes the typed text with it.
            if saved { dismiss() }
        }
    }
}
