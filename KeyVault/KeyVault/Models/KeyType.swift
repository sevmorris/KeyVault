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

    var systemImage: String {
        switch self {
        case .ssh: return "folder.badge.key"
        case .gpg: return "key"
        case .age: return "lock"
        case .api: return "key.2.on.key.fill"
        case .note: return "doc.text.fill"
        }
    }
}
