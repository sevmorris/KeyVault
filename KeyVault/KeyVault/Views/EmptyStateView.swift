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
        guard let type else { return "No Keys Found" }
        return "No \(type.rawValue) Keys"
    }

    private var subtitle: String {
        guard let type else { return "Add or generate a key to get started." }
        switch type {
        case .ssh: return "No SSH keys found in ~/.ssh/\nGenerate or import a key to get started."
        case .gpg: return "No GPG keys found.\nMake sure gpg is installed and keys are in your keyring."
        case .age: return "No Age keys found at configured paths.\nGenerate a key or update paths in Settings."
        case .api: return "No API keys stored.\nUse the + button to add an API key."
        }
    }
}
