import SwiftUI

@main
struct KeyVaultApp: App {
    /// Owned here, not in ContentView, so the menu bar can reach it. Menu
    /// commands are the only reliably visible controls in a Mac app — a
    /// toolbar button can be collapsed out of sight by a narrow window, which
    /// is exactly what happened to Backup and Settings when they lived only in
    /// the sidebar toolbar.
    @State private var viewModel = KeyVaultViewModel()

    var body: some Scene {
        WindowGroup {
            ContentView(viewModel: viewModel)
                .task {
                    // Silent at launch: only speaks up when there is something
                    // to say. Matches the sibling apps.
                    await checkForUpdates(silent: true)
                }
        }
        .defaultSize(width: 960, height: 580)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("New Note") { viewModel.showAddNoteSheet = true }
                    .keyboardShortcut("n", modifiers: .command)
                Button("New API Key") { viewModel.showAddAPIKeySheet = true }
                    .keyboardShortcut("n", modifiers: [.command, .shift])
                Divider()
                Button("Generate Key…") { viewModel.showGenerateSheet = true }
                Button("Import Key…") { viewModel.showImportSheet = true }
            }

            CommandGroup(after: .saveItem) {
                Divider()
                Button("Organise Notes…") { viewModel.showBulkCategorise = true }
                    .keyboardShortcut("o", modifiers: [.command, .shift])
                Button("Back Up & Restore…") { viewModel.showBackupSheet = true }
                    .keyboardShortcut("b", modifiers: [.command, .shift])
            }

            // The standard home for this on macOS is the app menu at ⌘,.
            CommandGroup(after: .appInfo) {
                Button("Check for Updates…") {
                    Task { await checkForUpdates(silent: false) }
                }
            }

            CommandGroup(replacing: .appSettings) {
                Button("Settings…") { viewModel.showSettings = true }
                    .keyboardShortcut(",", modifiers: .command)
            }

            CommandGroup(after: .toolbar) {
                Button("Refresh") { Task { await viewModel.reload() } }
                    .keyboardShortcut("r", modifiers: .command)
            }
        }
    }
}
