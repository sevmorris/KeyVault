import Foundation

enum KeyType: String, Codable, CaseIterable {
    case ssh = "SSH"
    case gpg = "GPG"
    case age = "Age"
    case api = "API Key"

    var systemImage: String {
        switch self {
        case .ssh: return "folder.badge.key"
        case .gpg: return "key"
        case .age: return "lock"
        case .api: return "key.2.on.key.fill"
        }
    }
}
