import SwiftUI

struct ImportKeyView: View {
    @Bindable var viewModel: KeyVaultViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var selectedURL: URL?
    @State private var isImporting = false
    @State private var errorMessage: String?
    @State private var showFilePicker = false

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "square.and.arrow.down")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)

            Text("Import Key")
                .font(.title2)
                .fontWeight(.semibold)

            // Age is not listed: importKey routes everything that is not a
            // .pub to gpg, so an Age key file only ever produced a confusing
            // gpg parse error. Add it here when there is something to add.
            Text("Import an SSH public key (.pub) or a GPG armored key file.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            if let url = selectedURL {
                HStack {
                    Image(systemName: "doc")
                    Text(url.lastPathComponent)
                        .font(.body)
                    Spacer()
                    Button {
                        selectedURL = nil
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                }
                .padding(10)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
            } else {
                Button {
                    showFilePicker = true
                } label: {
                    Label("Choose File…", systemImage: "folder")
                }
                .buttonStyle(.bordered)
            }

            if let error = errorMessage {
                Text(error)
                    .foregroundStyle(.red)
                    .font(.caption)
            }

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Import") {
                    Task { await doImport() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(selectedURL == nil || isImporting)
                .keyboardShortcut(.defaultAction)

                if isImporting {
                    ProgressView().controlSize(.small)
                }
            }
        }
        .padding(24)
        .frame(width: 400)
        .fileImporter(
            isPresented: $showFilePicker,
            allowedContentTypes: [.data],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls): selectedURL = urls.first
            case .failure(let error): errorMessage = error.localizedDescription
            }
        }
    }

    private func doImport() async {
        guard let url = selectedURL else { return }
        isImporting = true
        errorMessage = nil
        do {
            try await viewModel.importKey(from: url)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
        isImporting = false
    }
}
