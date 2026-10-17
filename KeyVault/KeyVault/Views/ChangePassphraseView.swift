import SwiftUI

/// Changes the master passphrase. Asks for the current one even though the
/// vault is open: an unlocked Mac left alone should not be enough to lock its
/// owner out of their own secrets.
struct ChangePassphraseView: View {
    @Bindable var viewModel: KeyVaultViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var current = ""
    @State private var new = ""
    @State private var confirmation = ""
    @State private var failure: String?
    @State private var working = false
    @FocusState private var focused: Bool

    private var problem: String? {
        if !new.isEmpty && new.count < 8 { return "At least 8 characters." }
        if !confirmation.isEmpty && new != confirmation { return "The two do not match." }
        if !new.isEmpty && new == current { return "That is the passphrase you have now." }
        return nil
    }

    private var canSubmit: Bool {
        !working && !current.isEmpty && new.count >= 8 && new == confirmation && new != current
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 8) {
                Label("Change the master passphrase", systemImage: "key.viewfinder")
                    .font(.headline)
                Text("""
                    Every note, API key and file is re-encrypted under the new \
                    passphrase. If KeyVault is stopped part way, it finishes or \
                    undoes the change the next time it opens.

                    Backups you have already made still open with the passphrase \
                    you gave each of them, not this one. Store the new passphrase \
                    in your password manager before you continue.
                    """)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            VStack(alignment: .leading, spacing: 10) {
                SecureField("Current passphrase", text: $current)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused)
                SecureField("New passphrase", text: $new)
                    .textFieldStyle(.roundedBorder)
                SecureField("Repeat new passphrase", text: $confirmation)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { if canSubmit { submit() } }
                if let problem {
                    Label(problem, systemImage: "info.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .disabled(working)

            if let failure {
                Label(failure, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    // Not while it runs: the change carries on regardless, and
                    // a closed sheet would hide whether it worked.
                    .disabled(working)
                Spacer()
                if working { ProgressView().controlSize(.small) }
                Button("Change Passphrase") { submit() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSubmit)
            }
        }
        .padding(24)
        .frame(width: 460)
        .interactiveDismissDisabled(working)
        .onAppear { focused = true }
    }

    private func submit() {
        working = true
        failure = nil
        let (current, new) = (current, new)
        Task {
            do {
                try await viewModel.changePassphrase(from: current, to: new)
                dismiss()
            } catch {
                failure = error.localizedDescription
                self.current = ""
            }
            working = false
        }
    }
}
