import Foundation
import Security

enum KeyError: LocalizedError {
    case toolNotFound(String)
    case parseFailed(String)
    case keychainError(OSStatus)
    case keygenFailed(String)
    case importFailed(String)
    case exportFailed(String)
    case deleteFailed(String)

    var errorDescription: String? {
        switch self {
        case .toolNotFound(let tool):
            return "Required tool not found: \(tool)"
        case .parseFailed(let detail):
            return "Failed to parse key data: \(detail)"
        case .keychainError(let status):
            // SecCopyErrorMessageString turns -25300 into "The specified item
            // could not be found in the keychain." The bare number is no use
            // to someone whose only copy of something just failed to save.
            let detail = SecCopyErrorMessageString(status, nil) as String?
            return detail.map { "Keychain error: \($0)" }
                ?? "Keychain error (OSStatus \(status))"
        case .keygenFailed(let detail):
            return "Key generation failed: \(detail)"
        case .importFailed(let detail):
            return "Key import failed: \(detail)"
        case .exportFailed(let detail):
            return "Key export failed: \(detail)"
        case .deleteFailed(let detail):
            return "Could not delete this key: \(detail)"
        }
    }
}
