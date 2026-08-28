import SwiftUI

struct ContentView: View {
    @State private var viewModel = KeyVaultViewModel()

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
        .sheet(isPresented: $viewModel.showGenerateSheet) {
            GenerateKeyView(viewModel: viewModel)
        }
        .sheet(isPresented: $viewModel.showImportSheet) {
            ImportKeyView(viewModel: viewModel)
        }
        .sheet(isPresented: $viewModel.showAddAPIKeySheet) {
            AddAPIKeyView(viewModel: viewModel)
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
