import SwiftUI

struct EmptyStateView: View {
    let type: KeyType?

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: systemImage)
                .font(.system(size: 48))
                .foregroundStyle(.tertiary)
            Text(title)
                .font(.headline)
                .foregroundStyle(.secondary)
            Text(subtitle)
                .font(.subheadline)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }

    private var systemImage: String {
        type?.systemImage ?? "key.fill"
    }

    private var title: String {
        // Appending "Keys" to every raw value read as "No Note Keys" and
        // "No API Key Keys". Notes are not keys, and the API label already
        // ends in one.
        guard let type else { return "Nothing Stored Yet" }
        switch type {
        case .note: return "No Notes"
        case .api: return "No API Keys"
        case .ssh, .gpg, .age: return "No \(type.rawValue) Keys"
        }
    }

    private var subtitle: String {
        guard let type else { return "Add a note or an API key to get started." }
        switch type {
        case .ssh: return "No SSH keys found in ~/.ssh/\nGenerate or import a key to get started."
        case .gpg: return "No GPG keys found.\nMake sure gpg is installed and keys are in your keyring."
        case .age: return "No Age keys found at configured paths.\nGenerate a key or update paths in Settings."
        case .api: return "No API keys stored.\nUse the + button to add an API key."
        case .note: return "No notes stored.\nUse the + button to add a secret note."
        }
    }
}
