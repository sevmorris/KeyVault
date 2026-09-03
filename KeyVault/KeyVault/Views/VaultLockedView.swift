import AppKit
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
    @State private var authenticating = false

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "lock.fill")
                .font(.system(size: 48))
                .foregroundStyle(.tertiary)

            Text(viewModel.isVaultSuspended ? "Locked after a spell of inactivity"
                                            : "KeyVault is locked")
                .font(.headline)
                .foregroundStyle(.secondary)

            Text(subtitle)
                .font(.subheadline)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 340)

            // Touch ID leads only where it can actually work — that is, where
            // the vault was shut by the timer rather than properly locked. The
            // passphrase is always on the screen beside it, because it is the
            // only thing that opens a vault from cold.
            if viewModel.canResumeWithBiometrics {
                VStack(spacing: 6) {
                    Button {
                        authenticate()
                    } label: {
                        Label("Unlock with Touch ID", systemImage: "touchid")
                    }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(authenticating)

                    Button("Use Passphrase…") { viewModel.showVaultUnlock = true }
                        .buttonStyle(.link)
                }
                .padding(.top, 4)
            } else {
                Button("Unlock…") { viewModel.showVaultUnlock = true }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .padding(.top, 4)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
        // Offered on arrival as well as on the button, so coming back to a
        // vault that locked itself is one touch rather than a click and then a
        // touch. Only ever on the resumable path — nothing prompts at launch.
        //
        // Gated on the app being frontmost, and repeated when it becomes so.
        // The lock usually fires *because* you are somewhere else, and a
        // system authentication dialog appearing over the window you are
        // actually working in is worse than the click it saves.
        .task {
            promptIfFrontmost()
            let activations = NotificationCenter.default.notifications(
                named: NSApplication.didBecomeActiveNotification
            )
            for await _ in activations { promptIfFrontmost() }
        }
    }

    private func promptIfFrontmost() {
        guard NSApp.isActive, viewModel.canResumeWithBiometrics else { return }
        authenticate()
    }

    private var subtitle: String {
        if viewModel.isVaultSuspended {
            return "Your notes and API keys are hidden until you unlock them again."
        }
        return "Your notes and API keys stay encrypted until you enter the master passphrase."
    }

    private func authenticate() {
        guard !authenticating else { return }
        authenticating = true
        Task {
            await viewModel.resumeWithBiometrics()
            authenticating = false
        }
    }
}
