import SwiftUI

/// What the window shows once the passphrase prompt has been dismissed and the
/// vault is still locked.
///
/// This is the state that makes cancelling safe to offer. Nothing stored is
/// loaded while it is on screen — see `KeyVaultViewModel.reload` — so the
/// window can be left open, or closed, without having listed the contents of
/// the vault to whoever walked away from the prompt.
struct VaultLockedView: View {
    let viewModel: KeyVaultViewModel

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "lock.fill")
                .font(.system(size: 48))
                .foregroundStyle(.tertiary)

            Text("KeyVault is locked")
                .font(.headline)
                .foregroundStyle(.secondary)

            Text("Your notes and API keys stay encrypted until you enter the master passphrase.")
                .font(.subheadline)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 340)

            Button("Unlock…") { viewModel.showVaultUnlock = true }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .padding(.top, 4)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}
