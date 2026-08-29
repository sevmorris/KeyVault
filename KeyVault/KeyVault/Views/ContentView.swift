import SwiftUI

struct ContentView: View {
    @Bindable var viewModel: KeyVaultViewModel

    var body: some View {
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
}
