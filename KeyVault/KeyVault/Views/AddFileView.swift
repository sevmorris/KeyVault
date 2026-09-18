import SwiftUI
import UniformTypeIdentifiers

/// Store a file, or rename one already stored.
///
/// One form for both, as AddNoteView is, but an edit asks fewer questions than
/// an add: a stored file's contents are not edited in place, so an edit is its
/// name and notes, and the file itself is shown rather than offered.
///
/// The Trash toggle starts on. What gets stored here is usually something just
/// exported and not meant to be left lying around — a password manager's CSV is
/// every password in plain text — and an encrypted copy beside an unencrypted
/// original protects nothing. It goes to the Trash rather than away, so a
/// mistake costs a drag back out, and emptying the Trash stays your decision.
struct AddFileView: View {
    let viewModel: KeyVaultViewModel

    /// The file being edited, or nil when adding one.
    var editing: EncryptionKey? = nil

    /// A file dropped on the list, which is what opened this sheet.
    var initialURL: URL? = nil

    @Environment(\.dismiss) private var dismiss

    @State private var fileURL: URL?
    @State private var fileSize: Int?
    @State private var name = ""
    @State private var notes = ""
    @State private var trashOriginal = true
    @State private var isChoosing = false
    @State private var isSaving = false
    @State private var errorMessage: String?
    @State private var didLoad = false

    private var isEditing: Bool { editing != nil }

    private var isValid: Bool {
        !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && (isEditing || fileURL != nil)
            && viewModel.isVaultConfigured
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(isEditing ? "Edit File" : "Add File")
                .font(.headline)
                .padding([.top, .horizontal])

            Form {
                Section {
                    fileRow
                    TextField("Name", text: $name, prompt: Text("e.g. NordPass export"))
                    TextField("Notes", text: $notes, axis: .vertical)
                        .lineLimit(2...4)
                    if !isEditing {
                        Toggle("Move the original to the Trash once it is stored", isOn: $trashOriginal)
                    }
                } footer: {
                    Text(footer)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)

            if !viewModel.isVaultConfigured {
                passphraseNeeded
            }

            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .padding(.horizontal)
            }

            HStack {
                if isSaving { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!isValid || isSaving)
            }
            .padding()
        }
        .frame(width: 460)
        .task { load() }
        .fileImporter(
            isPresented: $isChoosing,
            allowedContentTypes: [.data],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                if let url = urls.first { choose(url) }
            case .failure(let error):
                errorMessage = error.localizedDescription
            }
        }
    }

    @ViewBuilder private var fileRow: some View {
        if let editing {
            LabeledContent("File") {
                Text(describe(editing.fileName ?? editing.name, size: editing.fileSize))
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        } else {
            LabeledContent("File") {
                HStack {
                    if let fileURL {
                        Text(describe(fileURL.lastPathComponent, size: fileSize))
                            .lineLimit(1)
                            .truncationMode(.middle)
                    } else {
                        Text("Any file up to \(FileStore.maxFileSize.formatted(.byteCount(style: .file)))")
                            .foregroundStyle(.secondary)
                    }
                    Button(fileURL == nil ? "Choose…" : "Change…") { isChoosing = true }
                }
            }
        }
    }

    private var footer: String {
        if isEditing {
            return "Only the name and notes change. The file itself is left exactly as it is."
        }
        return """
            Encrypted with your master passphrase before it is written. The \
            original is not: it stays readable on disk until it is deleted, and \
            in the Trash until the Trash is emptied. Export an encrypted backup \
            before this is the only copy.
            """
    }

    /// Offered where the question arises. Files have no unencrypted fallback —
    /// see FileStore — so without a passphrase there is nothing Save could do.
    private var passphraseNeeded: some View {
        HStack {
            Label("Files are stored only under a master passphrase, and none is set yet.",
                  systemImage: "lock")
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            Button("Set One…") {
                dismiss()
                viewModel.showVaultSetup = true
            }
            .controlSize(.small)
        }
        .padding(.horizontal)
    }

    private func describe(_ fileName: String, size: Int?) -> String {
        guard let size else { return fileName }
        return "\(fileName) — \(size.formatted(.byteCount(style: .file)))"
    }

    /// Runs once: `.task` fires again if the view is reidentified, and loading
    /// again would throw away what has been typed since.
    private func load() {
        guard !didLoad else { return }
        didLoad = true
        if let editing {
            name = editing.name
            notes = editing.notes ?? ""
        } else if let initialURL {
            choose(initialURL)
        }
    }

    /// Take a file in, refusing here what Save would refuse later — a folder,
    /// or something too large — so nobody types a name and notes for a file
    /// that was never going to be stored.
    private func choose(_ url: URL) {
        errorMessage = nil
        do {
            fileSize = try FileStore.checkStorable(url.resolvingSymlinksInPath())
        } catch {
            errorMessage = error.localizedDescription
            return
        }
        // The name follows the file until it is typed over.
        let typed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if typed.isEmpty || typed == fileURL?.lastPathComponent {
            name = url.lastPathComponent
        }
        fileURL = url
    }

    private func save() {
        errorMessage = nil
        isSaving = true
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedNotes = notes.isEmpty ? nil : notes
        Task {
            do {
                if let editing {
                    try viewModel.updateFile(editing, name: trimmedName, notes: trimmedNotes)
                } else if let fileURL {
                    try await viewModel.addFile(from: fileURL, name: trimmedName,
                                                notes: trimmedNotes, trashOriginal: trashOriginal)
                }
                isSaving = false
                dismiss()
            } catch {
                // The sheet stays open over a failed save, with the reason,
                // and with everything typed still in it.
                isSaving = false
                errorMessage = error.localizedDescription
            }
        }
    }
}
