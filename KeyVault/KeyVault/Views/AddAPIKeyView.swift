import SwiftUI

struct AddAPIKeyView: View {
    @Bindable var viewModel: KeyVaultViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var service = ""
    @State private var secret = ""
    @State private var notes = ""
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    TextField("Name", text: $name, prompt: Text("e.g. GitHub Personal Access Token"))
                    TextField("Service / URL", text: $service, prompt: Text("https://github.com"))
                    SecureField("Secret Key / Token", text: $secret)
                    TextField("Notes", text: $notes, axis: .vertical)
                        .lineLimit(3...6)
                } footer: {
                    Text("The secret value is stored exclusively in the system Keychain and never written to disk or memory beyond what's required.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)

            if let error = errorMessage {
                Text(error)
                    .foregroundStyle(.red)
                    .font(.caption)
                    .padding(.horizontal)
            }

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Save") { save() }
                    .buttonStyle(.borderedProminent)
                    .disabled(!isValid)
                    .keyboardShortcut(.defaultAction)
            }
            .padding()
        }
        .frame(width: 440)
        .navigationTitle("Add API Key")
    }

    private var isValid: Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty &&
        !secret.isEmpty
    }

    private func save() {
        errorMessage = nil
        let key = EncryptionKey(
            type: .api,
            name: name.trimmingCharacters(in: .whitespaces),
            service: service.isEmpty ? nil : service,
            notes: notes.isEmpty ? nil : notes,
            createdDate: Date(),
            hasPrivateKey: false
        )
        do {
            try viewModel.addAPIKey(key: key, secret: secret)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
