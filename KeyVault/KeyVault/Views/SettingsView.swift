import SwiftUI

struct SettingsView: View {
    @Bindable var viewModel: KeyVaultViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var newPath = ""

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
            }
            .formStyle(.grouped)

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
