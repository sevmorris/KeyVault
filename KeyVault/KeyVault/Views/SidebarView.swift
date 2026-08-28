import SwiftUI

struct SidebarView: View {
    @Bindable var viewModel: KeyVaultViewModel

    var body: some View {
        List(selection: $viewModel.selectedType) {
            Section {
                Label("All Keys", systemImage: "key.fill")
                    .tag(Optional<KeyType>.none)
                    .badge(viewModel.allKeys.count)
            }

            Section("Key Types") {
                ForEach(KeyType.allCases, id: \.self) { type in
                    Label(type.rawValue, systemImage: type.systemImage)
                        .tag(Optional(type))
                        .badge(viewModel.keyCount(for: type))
                }
            }
        }
        .listStyle(.sidebar)
        .toolbar {
            ToolbarItem {
                Button {
                    viewModel.showBackupSheet = true
                } label: {
                    Image(systemName: "arrow.up.doc.on.clipboard")
                }
                .help("Backup & Restore")
            }
            ToolbarItem {
                Button {
                    viewModel.showSettings = true
                } label: {
                    Image(systemName: "gear")
                }
                .help("Settings")
            }
        }
    }
}
