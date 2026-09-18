import AppKit
import SwiftUI

/// A stored file's contents: shown when they are text, and written back out on
/// request.
///
/// Nothing here puts the contents on disk unasked. Opening the file in its own
/// app would mean decrypting it to a temporary file that outlives the viewing —
/// plaintext somewhere nobody chose, for as long as that app held it open. So
/// text is shown from memory, and everything leaves by Save a Copy, where you
/// choose the place and know what you have made.
///
/// Built fresh for each file — the caller keys it on the id — so one file's
/// contents never render in the next one's pane, and at most one file is in
/// memory at a time: the same rules the secret pane keeps.
struct FileContentsView: View {
    let key: EncryptionKey

    enum Preview: Equatable {
        case hidden
        case text(String, truncated: Bool)
        case binary
        case failed(String)
    }

    @State private var preview: Preview = .hidden
    @State private var saveStatus: String?
    @State private var saveError: String?

    /// How much of a text file is shown. The box is for checking you stored the
    /// right thing, not for reading a ten-thousand-line export, and laying all
    /// of one out would stall the pane. Save a Copy has the rest.
    static let previewLineLimit = 500
    static let previewCharacterLimit = 100_000

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Contents")
                    .font(.headline)
                Spacer()
                switch preview {
                case .text:
                    Button("Hide") { preview = .hidden }
                case .hidden:
                    Button("Reveal") { load() }
                case .binary, .failed:
                    EmptyView()
                }
                Button("Save a Copy…") { saveCopy() }
            }

            SecretBox {
                ScrollView {
                    VStack(alignment: .leading, spacing: 6) {
                        boxText
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            // A strip, not the whole pane, when there is nothing to show — for
            // the same reason a public key gets one: a line of explanation
            // above an acre of nothing. A text file keeps the whole box, hidden
            // or not, so Hide does not make the pane jump.
            .frame(maxHeight: preview == .binary ? 60 : .infinity)

            if let saveStatus {
                Text(saveStatus)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if let saveError {
                Text(saveError)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            if preview == .binary {
                Spacer(minLength: 0)
            }
        }
        .onAppear { load() }
    }

    @ViewBuilder private var boxText: some View {
        switch preview {
        case .text(let text, let truncated):
            Text(text)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
            if truncated {
                dim("Only the start of the file is shown. Save a Copy has all of it.")
            }
        case .binary:
            dim("This file is not text, so it is not shown here. Save a Copy to open it.")
        case .failed(let message):
            Text(message)
                .font(.callout)
                .foregroundStyle(.red)
        case .hidden:
            dim("Hidden.")
        }
    }

    private func dim(_ text: String) -> some View {
        Text(text)
            .font(.callout)
            .foregroundStyle(.secondary)
    }

    private func load() {
        do {
            preview = Self.preview(of: try FileStore.standard.loadContents(for: key.id))
        } catch {
            preview = .failed("Could not read this file: \(error.localizedDescription)")
        }
    }

    /// Text is whatever decodes as UTF-8 and holds no NUL. Every binary format
    /// worth worrying about has a NUL near the start, and text files have none.
    ///
    /// A long file is cut at a line end, never mid-line, and never by rewriting
    /// its line ends — CRLF stays CRLF — so what is shown is the file's own
    /// text, only less of it.
    static func preview(of data: Data) -> Preview {
        guard !data.contains(0), let text = String(data: data, encoding: .utf8) else {
            return .binary
        }
        var end = text.endIndex
        var lines = 0
        var cursor = text.startIndex
        while let newline = text[cursor...].firstIndex(where: \.isNewline) {
            lines += 1
            cursor = text.index(after: newline)
            if lines == previewLineLimit {
                // A file of exactly this many lines has only its last line end
                // left over, and is not cut short by losing it.
                if cursor < text.endIndex { end = newline }
                break
            }
        }
        let shown = text[..<end].prefix(previewCharacterLimit)
        return .text(String(shown), truncated: shown.endIndex != text.endIndex)
    }

    private func saveCopy() {
        saveStatus = nil
        saveError = nil
        let panel = NSSavePanel()
        panel.nameFieldStringValue = key.fileName ?? key.name
        panel.canCreateDirectories = true
        panel.message = "The copy is not encrypted. Delete it when you are done with it."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let contents = try FileStore.standard.loadContents(for: key.id)
            try contents.write(to: url, options: .atomic)
            // Owner-only, as ~/.ssh keys are: this is the secret in the clear,
            // and nothing else on this Mac needs to read it.
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            saveStatus = "Saved an unencrypted copy as \(url.lastPathComponent)."
        } catch {
            saveError = "Could not save a copy: \(error.localizedDescription)"
        }
    }
}
