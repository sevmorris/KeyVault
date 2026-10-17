import SwiftUI

struct SettingsView: View {
    @Bindable var viewModel: KeyVaultViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var newPath = ""
    @State private var plaintextRemaining = 0

    /// The settings being edited, copied from the view model when the sheet
    /// opens and handed back only by Save.
    ///
    /// Binding the form straight to `viewModel.settings` made Cancel a lie:
    /// every change landed the moment it was made, so the idle-lock picker
    /// took effect at once, a removed Age path stayed removed, and Cancel only
    /// skipped writing them to disk, so they held until the app quit.
    @State private var draft: AppSettings

    init(viewModel: KeyVaultViewModel) {
        self.viewModel = viewModel
        _draft = State(initialValue: viewModel.settings)
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    ForEach(draft.ageKeyPaths, id: \.self) { path in
                        HStack {
                            Text(path)
                                .font(.system(.body, design: .monospaced))
                                .foregroundStyle(.primary)
                            Spacer()
                            Button {
                                draft.ageKeyPaths.removeAll { $0 == path }
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
                                  !draft.ageKeyPaths.contains(trimmed) else { return }
                            draft.ageKeyPaths.append(trimmed)
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
                            Text(viewModel.vaultIsLocked ? "Set — vault locked" : "Set")
                                .foregroundStyle(.secondary)
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
                                .disabled(viewModel.vaultIsLocked)
                            }
                        } else {
                            Label("All secrets are encrypted", systemImage: "checkmark.seal.fill")
                                .foregroundStyle(.green)
                            Button("Repair Keychain Access") {
                                Task { await viewModel.encryptExistingSecrets() }
                            }
                            .disabled(viewModel.vaultIsLocked)
                        }
                        Picker("Lock when idle", selection: $draft.idleLockMinutes) {
                            Text("Never").tag(0)
                            Text("After 1 minute").tag(1)
                            Text("After 5 minutes").tag(5)
                            Text("After 15 minutes").tag(15)
                            Text("After 30 minutes").tag(30)
                            Text("After 1 hour").tag(60)
                        }

                        // Reachable while locked — Settings is still on ⌘, —
                        // so it offers the way back in rather than a Lock
                        // button for a vault that is already locked.
                        if viewModel.vaultIsLocked {
                            Button("Unlock Vault…") {
                                dismiss()
                                viewModel.showVaultUnlock = true
                            }
                        } else {
                            Button("Change Passphrase…") {
                                dismiss()
                                viewModel.showChangePassphrase = true
                            }
                            Button("Lock Vault Now") {
                                viewModel.lockVault()
                                dismiss()
                            }
                            .help("Forgets the passphrase — Touch ID cannot reopen it")
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
                         ? "Secrets are encrypted with your master passphrase before they are stored, so nothing else on this Mac can read them. The vault locks when left idle and whenever the Mac sleeps, locks its screen or switches user; Touch ID can reopen it then, on a Mac that has it. Lock Vault Now forgets the passphrase, so only typing it again will open the vault. Repair Keychain Access widens the Keychain permissions on items saved by earlier versions, which stops macOS asking for your login password once per note after the app is rebuilt or re-signed. Notes first saved as plain text by this version keep KeyVault as their only trusted app, because widening them would itself ask for permission once per note."
                         : "Without a master passphrase, notes and API keys are stored as plain text. Other apps have to be allowed at a prompt to read one saved by this version, but any app can read those saved by earlier versions, without asking, until they are encrypted. Setting one encrypts them before they are stored, and lets KeyVault store files, which it keeps only encrypted.")
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
                    viewModel.saveSettings(draft)
                    Task { await viewModel.reload() }
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
            }
            .padding()
        }
        .frame(width: 480, height: 440)
        .navigationTitle("Settings")
    }
}
