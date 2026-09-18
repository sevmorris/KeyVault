import Foundation

enum KeyType: String, Codable, CaseIterable {
    case ssh = "SSH"
    case gpg = "GPG"
    case age = "Age"
    case api = "API Key"
    /// A titled, multi-line secret KeyVault owns outright — recovery codes,
    /// account numbers, licence keys. Unlike SSH/GPG/Age, which index key
    /// material already on disk, nothing else holds a copy of these.
    case note = "Note"
    /// A whole file KeyVault keeps encrypted in its own folder — a password
    /// manager's export, a service-account key. Once the original is gone,
    /// this is the only copy, exactly as a note is.
    case file = "File"

    var systemImage: String {
        switch self {
        case .ssh: return "folder.badge.key"
        case .gpg: return "key"
        case .age: return "lock"
        case .api: return "key.2.on.key.fill"
        case .note: return "doc.text.fill"
        case .file: return "doc.fill"
        }
    }

    /// Whether KeyVault holds this itself — notes and API keys in the
    /// Keychain, files in its own encrypted folder — rather than indexing key
    /// material another tool owns. These are what the encrypted backup
    /// carries, and what locking the vault clears from memory.
    ///
    /// A switch rather than a set, so that a type added later has to be put
    /// on one side or the other before anything compiles.
    var isStored: Bool {
        switch self {
        case .note, .api, .file: return true
        case .ssh, .gpg, .age: return false
        }
    }
}
