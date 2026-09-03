import Foundation
import LocalAuthentication

/// Touch ID, used for one narrow job: bringing back a vault this run of the
/// app already had open.
///
/// LocalAuthentication answers a yes/no question — it hands back no key
/// material — so it can never be what opens an encrypted vault from cold. See
/// `VaultCrypto.suspend()` for why that distinction decides the whole design.
/// It needs no entitlement and no provisioning profile, which is the reason it
/// is reachable here at all where the Keychain's own biometric gating is not.
enum BiometricAuth {
    enum Outcome {
        case success
        /// The user dismissed the prompt. Not a failure worth reporting: they
        /// were there, and they said no.
        case cancelled
        case failed(String)
    }

    /// Whether a fingerprint can be asked for *right now* — sensor present, a
    /// finger enrolled, and not locked out after too many bad reads.
    static var isAvailable: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                      error: nil)
    }

    /// Biometrics only, never `.deviceOwnerAuthentication`. The fallback that
    /// policy offers is the Mac's login password, which would quietly make a
    /// second, unrelated secret sufficient to open the vault. The passphrase is
    /// the fallback here, and it is on the same screen.
    static func authenticate(reason: String) async -> Outcome {
        let context = LAContext()
        context.localizedFallbackTitle = ""

        var probe: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                        error: &probe) else {
            return .failed(probe?.localizedDescription ?? "Touch ID is not available.")
        }

        return await withCheckedContinuation { continuation in
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                   localizedReason: reason) { ok, error in
                if ok {
                    continuation.resume(returning: .success)
                    return
                }
                let code = (error as? LAError)?.code
                switch code {
                case .userCancel, .systemCancel, .appCancel:
                    continuation.resume(returning: .cancelled)
                default:
                    continuation.resume(
                        returning: .failed(error?.localizedDescription
                                           ?? "Touch ID could not verify you.")
                    )
                }
            }
        }
    }
}
