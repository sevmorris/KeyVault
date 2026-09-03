import SwiftUI

struct ContentView: View {
    @Bindable var viewModel: KeyVaultViewModel

    var body: some View {
        Group {
            // Cancelling the passphrase prompt has to land somewhere honest.
            // The alternative — the window as normal, every row failing when
            // opened — would list the name of everything in the vault to
            // whoever dismissed the prompt, which is most of what they wanted.
            if viewModel.vaultIsLocked {
                VaultLockedView(viewModel: viewModel)
            } else {
                vault
            }
        }
        .sheet(isPresented: $viewModel.showGenerateSheet) {
            GenerateKeyView(viewModel: viewModel)
        }
        .sheet(isPresented: $viewModel.showImportSheet) {
            ImportKeyView(viewModel: viewModel)
        }
        .sheet(isPresented: $viewModel.showAddAPIKeySheet) {
            AddAPIKeyView(viewModel: viewModel)
        }
        .sheet(isPresented: $viewModel.showAddNoteSheet) {
            AddNoteView(viewModel: viewModel)
        }
        .sheet(isPresented: $viewModel.showBackupSheet) {
            BackupView(viewModel: viewModel)
        }
        // The door — and one you can turn away from. It was previously
        // presented by a binding on the locked state itself and could not be
        // dismissed, which made force-quitting the only way to close a vault
        // you had opened by mistake. Cancelling now leaves the window locked
        // rather than leaving the app unusable.
        .sheet(isPresented: $viewModel.showVaultUnlock) {
            VaultLockView(mode: .unlock, onSuccess: { _ in
                viewModel.showVaultUnlock = false
                viewModel.vaultDidUnlock()
                Task { await viewModel.reload() }
            }, onCancel: { viewModel.showVaultUnlock = false })
        }
        .sheet(isPresented: $viewModel.showVaultSetup) {
            VaultLockView(mode: .setup, onSuccess: { wasSetup in
                viewModel.showVaultSetup = false
                viewModel.vaultDidUnlock()
                viewModel.offerEncryptExisting = wasSetup
            }, onCancel: { viewModel.showVaultSetup = false })
        }
        .alert("Encrypt what is already stored?",
               isPresented: $viewModel.offerEncryptExisting) {
            Button("Encrypt Now") { Task { await viewModel.encryptExistingSecrets() } }
            Button("Later", role: .cancel) { }
        } message: {
            Text("""
                Secrets saved before now are still stored as plain text and \
                readable by anything running as you. Back up first if you have \
                not — this cannot be undone without your passphrase.
                """)
        }
        .sheet(isPresented: $viewModel.showBulkCategorise) {
            BulkCategoriseView(viewModel: viewModel)
        }
        .sheet(isPresented: $viewModel.showSettings) {
            SettingsView(viewModel: viewModel)
        }
        .alert("Error", isPresented: .init(
            get: { viewModel.errorMessage != nil },
            set: { if !$0 { viewModel.errorMessage = nil } }
        )) {
            Button("OK") { viewModel.errorMessage = nil }
        } message: {
            Text(viewModel.errorMessage ?? "")
        }
        .task {
            await viewModel.reload()
        }
    }

    /// The app proper: sidebar, list, detail, and the toolbar that belongs to
    /// all three.
    private var vault: some View {
        NavigationSplitView {
            SidebarView(viewModel: viewModel)
        } content: {
            KeyListView(viewModel: viewModel)
        } detail: {
            if let key = viewModel.selectedKey {
                KeyDetailView(viewModel: viewModel, key: key)
            } else {
                EmptyStateView(type: viewModel.selectedType)
            }
        }
        // Attached to the NavigationSplitView, not to a column. A column's
        // .toolbar is confined to that column's slice of the toolbar, so the
        // sidebar's ~220pt gave Backup and Settings nowhere to render and they
        // collapsed into the overflow chevron regardless of window width.
        .toolbar {
            ToolbarItemGroup {
                Button { viewModel.showAddNoteSheet = true } label: {
                    Label("Add Note", systemImage: "doc.badge.plus")
                }
                .help("Add Note")

                Button { viewModel.showAddAPIKeySheet = true } label: {
                    Label("Add API Key", systemImage: "key.horizontal")
                }
                .help("Add API Key")

                Button { viewModel.showImportSheet = true } label: {
                    Label("Import Key", systemImage: "square.and.arrow.down")
                }
                .help("Import Key")

                Button { viewModel.showGenerateSheet = true } label: {
                    Label("Generate Key", systemImage: "wand.and.stars")
                }
                .help("Generate Key")

                Button { Task { await viewModel.reload() } } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .help("Refresh")

                Button { viewModel.showBackupSheet = true } label: {
                    Label("Backup & Restore", systemImage: "arrow.up.doc.on.clipboard")
                }
                .help("Backup & Restore")

                Button { viewModel.showSettings = true } label: {
                    Label("Settings", systemImage: "gear")
                }
                .help("Settings")
            }
        }
    }
}
