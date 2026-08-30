import SwiftUI

/// Sets the master passphrase, or unlocks with it.
///
/// One view rather than two because the fields, the warnings and the failure
/// text are nearly identical, and the difference — a confirmation field and a
/// much louder warning — is easier to keep honest side by side than in two
/// files that drift.
struct VaultLockView: View {
    enum Mode {
        case setup
        case unlock
    }

    let mode: Mode
    /// Called on success. Setup passes `true` so the caller can offer to
    /// encrypt what is already stored, which is the only moment the user is
    /// obviously thinking about it.
    let onSuccess: (_ wasSetup: Bool) -> Void
    let onCancel: (() -> Void)?

    @State private var passphrase = ""
    @State private var confirmation = ""
    @State private var failure: String?
    @State private var working = false
    @FocusState private var focused: Bool

    private var canSubmit: Bool {
        guard !working, !passphrase.isEmpty else { return false }
        if mode == .setup {
            return passphrase.count >= 8 && passphrase == confirmation
        }
        return true
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            header

            VStack(alignment: .leading, spacing: 10) {
                SecureField(mode == .setup ? "New passphrase" : "Passphrase", text: $passphrase)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused)
                    .onSubmit { if canSubmit { submit() } }

                if mode == .setup {
                    SecureField("Repeat passphrase", text: $confirmation)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit { if canSubmit { submit() } }

                    if !passphrase.isEmpty && passphrase.count < 8 {
                        Label("At least 8 characters.", systemImage: "info.circle")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else if !confirmation.isEmpty && passphrase != confirmation {
                        Label("The two do not match.", systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }
            }

            if let failure {
                Label(failure, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                if let onCancel {
                    Button("Cancel") { onCancel() }
                        .keyboardShortcut(.cancelAction)
                }
                Spacer()
                Button(mode == .setup ? "Set Passphrase" : "Unlock") { submit() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSubmit)
            }
        }
        .padding(24)
        .frame(width: 440)
        .onAppear { focused = true }
    }

    @ViewBuilder
    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(mode == .setup ? "Set a master passphrase" : "Unlock KeyVault",
                  systemImage: mode == .setup ? "lock.badge.clock" : "lock.fill")
                .font(.headline)

            if mode == .setup {
                // Stated before the fields, not after: this is the decision, and
                // it is not reversible by anything KeyVault can do.
                Text("""
                    Your notes and API keys are encrypted with this passphrase \
                    before they are stored, so nothing else on this Mac can read \
                    them — not another app, and not a script.

                    There is no way to recover it. If you forget it, the only way \
                    back into your secrets is a Backup & Restore archive and the \
                    passphrase for that. Store it in your password manager now.
                    """)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("Your vault is encrypted. Enter the master passphrase to open it.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func submit() {
        working = true
        failure = nil
        // Off the main thread: PBKDF2 at 600k iterations is deliberately slow,
        // and beachballing the window while it runs looks like a hang.
        let entered = passphrase
        Task.detached {
            do {
                if mode == .setup {
                    try VaultCrypto.configure(passphrase: entered)
                    await finish(ok: true)
                } else {
                    let ok = try VaultCrypto.unlock(passphrase: entered)
                    await finish(ok: ok, message: ok ? nil : "That passphrase is not correct.")
                }
            } catch {
                await finish(ok: false, message: error.localizedDescription)
            }
        }
    }

    @MainActor
    private func finish(ok: Bool, message: String? = nil) {
        working = false
        if ok {
            passphrase = ""
            confirmation = ""
            onSuccess(mode == .setup)
        } else {
            failure = message ?? "Could not unlock the vault."
            passphrase = ""
        }
    }
}
