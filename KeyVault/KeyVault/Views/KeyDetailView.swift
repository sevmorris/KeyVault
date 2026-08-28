import SwiftUI

struct KeyDetailView: View {
    @Bindable var viewModel: KeyVaultViewModel
    let key: EncryptionKey
    @State private var showDeleteConfirm = false
    @State private var deleteError: String?
    @State private var copied = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                Divider()
                metadata
                if let pubKey = key.publicKey, !pubKey.isEmpty {
                    Divider()
                    publicKeySection(pubKey)
                }
                Spacer()
                deleteSection
            }
            .padding(20)
        }
        .navigationTitle(key.name)
        .alert("Delete Key?", isPresented: $showDeleteConfirm) {
            Button("Delete", role: .destructive) {
                Task {
                    do {
                        try await viewModel.deleteKey(key)
                    } catch {
                        deleteError = error.localizedDescription
                    }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(deleteMessage)
        }
        .alert("Delete Failed", isPresented: .init(
            get: { deleteError != nil },
            set: { if !$0 { deleteError = nil } }
        )) {
            Button("OK") { deleteError = nil }
        } message: {
            Text(deleteError ?? "")
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: key.type.systemImage)
                .font(.system(size: 32))
                .foregroundStyle(Color.accentColor)
            VStack(alignment: .leading, spacing: 2) {
                Text(key.name)
                    .font(.title2)
                    .fontWeight(.semibold)
                Text(key.type.rawValue)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
    }

    private var metadata: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let algorithm = key.algorithm {
                DetailRow(label: "Algorithm", value: algorithm)
            }
            if let fingerprint = key.fingerprint {
                HStack {
                    DetailRow(label: "Fingerprint", value: fingerprint)
                    Button {
                        viewModel.copyFingerprint(key)
                        flashCopied()
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .buttonStyle(.plain)
                    .help("Copy Fingerprint")
                }
            }
            if let keyID = key.keyID {
                DetailRow(label: "Key ID", value: keyID)
            }
            if let path = key.path {
                DetailRow(label: "Path", value: path)
            }
            if let service = key.service {
                DetailRow(label: "Service", value: service)
            }
            if let created = key.createdDate {
                DetailRow(label: "Created", value: created.formatted(date: .abbreviated, time: .omitted))
            }
            if let expiry = key.expiryDate {
                DetailRow(label: "Expires", value: expiry.formatted(date: .abbreviated, time: .omitted))
                    .foregroundStyle(expiry < Date() ? .red : .primary)
            }
            if key.hasPrivateKey {
                DetailRow(label: "Private Key", value: "Present")
            }
            if let notes = key.notes, !notes.isEmpty {
                DetailRow(label: "Notes", value: notes)
            }
        }
    }

    private func publicKeySection(_ pubKey: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Public Key")
                    .font(.headline)
                Spacer()
                Button {
                    viewModel.copyPublicKey(key)
                    flashCopied()
                } label: {
                    Label(copied ? "Copied!" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .animation(.easeInOut(duration: 0.2), value: copied)
            }
            ScrollView(.horizontal, showsIndicators: false) {
                Text(pubKey)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(8)
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
            }
        }
    }

    private var deleteSection: some View {
        HStack {
            Spacer()
            Button(role: .destructive) {
                showDeleteConfirm = true
            } label: {
                Label("Delete Key", systemImage: "trash")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .tint(.red)
        }
    }

    private var deleteMessage: String {
        switch key.type {
        case .ssh:
            return "This will permanently delete the key file(s) from ~/.ssh/. This cannot be undone."
        case .gpg:
            return "This will remove the key from your GPG keyring. This cannot be undone."
        case .age:
            return "Age key deletion is not supported. Please edit the key file manually."
        case .api:
            return "This will delete the API key from the Keychain. This cannot be undone."
        }
    }

    private func flashCopied() {
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            copied = false
        }
    }
}

private struct DetailRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            Text(label + ":")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .frame(width: 100, alignment: .leading)
            Text(value)
                .font(.subheadline)
                .textSelection(.enabled)
        }
    }
}
