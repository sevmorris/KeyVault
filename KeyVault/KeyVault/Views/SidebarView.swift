import SwiftUI

struct SidebarView: View {
    @Bindable var viewModel: KeyVaultViewModel

    var body: some View {
        List(selection: $viewModel.sidebarSelection) {
            Section("Secrets") {
                ForEach(secretTypes, id: \.self) { type in
                    Label(type.rawValue, systemImage: type.systemImage)
                        .tag(SidebarSelection.type(type))
                        .badge(viewModel.keyCount(for: type))
                }
            }

            // Keys sit below the secrets, and only the ones actually present
            // show up. SSH, GPG and Age are a view onto files and keyrings that
            // their own tools own — the encrypted backup covers none of them —
            // so they are an inventory rather than the point of the app, and a
            // flat list of all five put them in front of the thing that is.
            if !presentKeyTypes.isEmpty {
                Section("Keys") {
                    ForEach(presentKeyTypes, id: \.self) { type in
                        Label(type.rawValue, systemImage: type.systemImage)
                            .tag(SidebarSelection.type(type))
                            .badge(viewModel.keyCount(for: type))
                    }
                }
            }

            Section {
                Label("Everything", systemImage: "tray.full")
                    .tag(SidebarSelection.everything)
                    .badge(viewModel.allKeys.count)
            }
        }
        .listStyle(.sidebar)
    }

    /// The types the store owns outright — the ones it can back up, restore
    /// and rewrite, and the reason the app exists.
    private var secretTypes: [KeyType] {
        ordered(KeyType.allCases.filter { SecretStore.ownedTypes.contains($0) })
    }

    /// Everything else, minus whatever there is none of: with no age-keygen
    /// installed, Age drops out of the sidebar rather than sitting at zero
    /// advertising a section that can never fill.
    private var presentKeyTypes: [KeyType] {
        ordered(KeyType.allCases.filter { !SecretStore.ownedTypes.contains($0) })
            .filter { viewModel.keyCount(for: $0) > 0 }
    }

    /// Preferred display order. The two groups are derived from `ownedTypes`
    /// rather than hand-listed, so a KeyType added later lands in the right
    /// section instead of quietly going missing from the sidebar; anything not
    /// named here sorts to the end of its group.
    private func ordered(_ types: [KeyType]) -> [KeyType] {
        let preferred: [KeyType] = [.note, .api, .ssh, .gpg, .age]
        return types.sorted {
            (preferred.firstIndex(of: $0) ?? .max) < (preferred.firstIndex(of: $1) ?? .max)
        }
    }
}
