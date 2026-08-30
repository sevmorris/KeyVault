import SwiftUI

struct SettingsView: View {
    @Bindable var viewModel: KeyVaultViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var newPath = ""
    @State private var plaintextRemaining = 0

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    ForEach(viewModel.settings.ageKeyPaths, id: \.self) { path in
                        HStack {
                            Text(path)
                                .font(.system(.body, design: .monospaced))
                                .foregroundStyle(.primary)
                            Spacer()
                            Button {
                                viewModel.settings.ageKeyPaths.removeAll { $0 == path }
                            } label: {
                                Image(systemName: "minus.circle.fill")
                                    .foregroundStyle(.red)
                            }
                            .buttonStyle(.plain)
                        }
                    }

                    HStack {
                        TextField("Add path…", text: $newPath, prompt: Text("~/.config/sops/age/keys.txt"))
                            .font(.system(.body, design: .monospaced))
                        Button {
                            let trimmed = newPath.trimmingCharacters(in: .whitespaces)
                            guard !trimmed.isEmpty,
                                  !viewModel.settings.ageKeyPaths.contains(trimmed) else { return }
                            viewModel.settings.ageKeyPaths.append(trimmed)
                            newPath = ""
                        } label: {
                            Image(systemName: "plus.circle.fill")
                                .foregroundStyle(Color.accentColor)
                        }
                        .buttonStyle(.plain)
                        .disabled(newPath.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                } header: {
                    Text("Age Key File Paths")
                } footer: {
                    Text("KeyVault scans these files for Age keys. SSH keys are always loaded from ~/.ssh/. GPG keys are loaded from the system GPG keyring.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section {
                    if viewModel.isVaultConfigured {
                        LabeledContent("Master passphrase") {
                            Text("Set").foregroundStyle(.secondary)
                        }
                        if plaintextRemaining > 0 {
                            HStack {
                                Label("\(plaintextRemaining) secret(s) still stored as plain text",
                                      systemImage: "exclamationmark.triangle.fill")
                                    .foregroundStyle(.orange)
                                Spacer()
                                Button("Encrypt Now") {
                                    Task {
                                        await viewModel.encryptExistingSecrets()
                                        plaintextRemaining = SecretStore.plaintextCount()
                                    }
                                }
                            }
                        } else {
                            Label("All secrets are encrypted", systemImage: "checkmark.seal.fill")
                                .foregroundStyle(.green)
                            Button("Repair Keychain Access") {
                                Task { await viewModel.encryptExistingSecrets() }
                            }
                        }
                        Button("Lock Vault Now") {
                            viewModel.lockVault()
                            dismiss()
                        }
                    } else {
                        Button("Set a Master Passphrase…") {
                            dismiss()
                            viewModel.showVaultSetup = true
                        }
                    }
                } header: {
                    Text("Security")
                } footer: {
                    Text(viewModel.isVaultConfigured
                         ? "Secrets are encrypted with your master passphrase before they are stored, so nothing else on this Mac can read them. Repair Keychain Access widens the Keychain permissions on every item, which stops macOS asking for your login password once per note after the app is rebuilt or re-signed."
                         : "Without a master passphrase, notes and API keys are stored where any process running as you can read them. Setting one encrypts them before they are stored.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)
            .onAppear { plaintextRemaining = SecretStore.plaintextCount() }

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Save") {
                    viewModel.saveSettings()
                    Task { await viewModel.reload() }
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
            }
            .padding()
        }
        .frame(width: 480, height: 360)
        .navigationTitle("Settings")
    }
}
