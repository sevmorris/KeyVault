import SwiftUI

struct GenerateKeyView: View {
    @Bindable var viewModel: KeyVaultViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var selectedType: KeyType = .ssh
    @State private var isGenerating = false
    @State private var errorMessage: String?

    // SSH fields
    @State private var sshAlgorithm = "ed25519"
    @State private var sshBits = ""
    @State private var sshComment = ""
    @State private var sshPath = NSHomeDirectory() + "/.ssh/id_ed25519"
    @State private var sshPassphrase = ""

    // GPG fields
    @State private var gpgName = ""
    @State private var gpgEmail = ""
    @State private var gpgAlgorithm = "RSA"
    @State private var gpgExpiry = "0"

    // Age fields
    @State private var agePath = "~/.age/keys.txt"

    private let sshAlgorithms = ["ed25519", "rsa", "ecdsa"]
    private let gpgAlgorithms = ["RSA", "DSA", "ECDSA"]

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Picker("Key Type", selection: $selectedType) {
                    ForEach(KeyType.allCases.filter { !SecretStore.ownedTypes.contains($0) }, id: \.self) { type in
                        Text(type.rawValue).tag(type)
                    }
                }
                .pickerStyle(.segmented)
                .padding(.bottom, 8)

                switch selectedType {
                case .ssh:
                    sshForm
                case .gpg:
                    gpgForm
                case .age:
                    ageForm
                case .api, .note:
                    // Stored, not generated — filtered out of the picker above.
                    EmptyView()
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
                Button("Generate") {
                    Task { await generate() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isGenerating || !isValid)
                .keyboardShortcut(.defaultAction)

                if isGenerating {
                    ProgressView().controlSize(.small)
                }
            }
            .padding()
        }
        .frame(width: 480)
        .navigationTitle("Generate Key")
        .onChange(of: sshAlgorithm) { _, alg in
            let defaultName = "id_\(alg)"
            sshPath = NSHomeDirectory() + "/.ssh/\(defaultName)"
        }
    }

    private var sshForm: some View {
        Group {
            Picker("Algorithm", selection: $sshAlgorithm) {
                ForEach(sshAlgorithms, id: \.self) { Text($0).tag($0) }
            }
            if sshAlgorithm == "rsa" {
                TextField("Bits (e.g. 4096)", text: $sshBits)
            }
            TextField("Comment", text: $sshComment, prompt: Text("user@host"))
            TextField("File Path", text: $sshPath)
            SecureField("Passphrase (leave blank for none)", text: $sshPassphrase)
        }
    }

    private var gpgForm: some View {
        Group {
            TextField("Full Name", text: $gpgName)
            TextField("Email", text: $gpgEmail)
            Picker("Algorithm", selection: $gpgAlgorithm) {
                ForEach(gpgAlgorithms, id: \.self) { Text($0).tag($0) }
            }
            TextField("Expiry (0 = never, or e.g. 1y, 6m)", text: $gpgExpiry)
        }
    }

    private var ageForm: some View {
        Group {
            TextField("Output File Path", text: $agePath)
            Text("The Age key file will contain both the private and public key. Keep it safe.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var isValid: Bool {
        switch selectedType {
        case .ssh: return !sshPath.isEmpty
        case .gpg: return !gpgName.isEmpty && !gpgEmail.isEmpty
        case .age: return !agePath.isEmpty
        case .api, .note: return false
        }
    }

    private func generate() async {
        isGenerating = true
        errorMessage = nil
        do {
            switch selectedType {
            case .ssh:
                let bits = Int(sshBits)
                try await viewModel.generateSSHKey(
                    algorithm: sshAlgorithm,
                    bits: bits,
                    comment: sshComment,
                    path: (sshPath as NSString).expandingTildeInPath,
                    passphrase: sshPassphrase
                )
            case .gpg:
                try await viewModel.generateGPGKey(
                    name: gpgName,
                    email: gpgEmail,
                    algorithm: gpgAlgorithm,
                    expiry: gpgExpiry
                )
            case .age:
                try await viewModel.generateAgeKey(outputPath: agePath)
            case .api, .note:
                break
            }
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
        isGenerating = false
    }
}
