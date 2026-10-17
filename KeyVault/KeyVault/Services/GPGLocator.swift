import Foundation

/// Where `gpg` lives.
///
/// A GUI app does not inherit the shell's PATH — it gets a minimal one that
/// has never heard of Homebrew — so the binary has to be found by absolute
/// path. This lives in one place because it was previously spelled twice, in
/// opposite orders: on a Mac carrying both an Intel-era `/usr/local/bin/gpg`
/// and an Apple-silicon `/opt/homebrew/bin/gpg`, listing keys and exporting
/// the vault could each pick a different binary, with different versions and
/// potentially a different `~/.gnupg`.
enum GPGLocator {
    /// Apple-silicon Homebrew first, then Intel Homebrew, then GPG Suite —
    /// the other common way GnuPG reaches a Mac, which installs here and links
    /// nothing into /usr/local/bin — then anything the system supplies.
    static let searchPaths = [
        "/opt/homebrew/bin/gpg",
        "/usr/local/bin/gpg",
        "/usr/local/MacGPG2/bin/gpg",
        "/usr/bin/gpg"
    ]

    static var isAvailable: Bool { (try? resolve()) != nil }

    static func resolve() throws -> String {
        guard let path = searchPaths.first(where: {
            FileManager.default.fileExists(atPath: $0)
        }) else {
            throw KeyError.toolNotFound("gpg")
        }
        return path
    }
}
