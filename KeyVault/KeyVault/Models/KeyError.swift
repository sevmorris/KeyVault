import Foundation

enum KeyError: LocalizedError {
    case toolNotFound(String)
    case parseFailed(String)
    case keychainError(OSStatus)
    case keygenFailed(String)
    case importFailed(String)
    case exportFailed(String)

    var errorDescription: String? {
        switch self {
        case .toolNotFound(let tool):
            return "Required tool not found: \(tool)"
        case .parseFailed(let detail):
            return "Failed to parse key data: \(detail)"
        case .keychainError(let status):
            return "Keychain error (OSStatus \(status))"
        case .keygenFailed(let detail):
            return "Key generation failed: \(detail)"
        case .importFailed(let detail):
            return "Key import failed: \(detail)"
        case .exportFailed(let detail):
            return "Key export failed: \(detail)"
        }
    }
}
