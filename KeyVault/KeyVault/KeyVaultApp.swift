import SwiftUI

/// Decides, before anything else runs, whether this launch is the app or only
/// the host for the unit tests.
///
/// Xcode runs the tests inside this app, so a test launch would otherwise start
/// all of it: the view model would read the Keychain and ~/.ssh, the vault would
/// put up its unlock prompt, the settings would load and save, and the update
/// check would run. Hosting tests, the app starts with no window, no view model
/// and no update check. Magic Backup Machine's pattern, as every sibling app
/// uses it.
@main
enum AppLauncher {
    static func main() {
        if isHostingTests {
            TestHostApp.main()
        } else {
            KeyVaultApp.main()
        }
    }

    /// XCTest is already loaded when main() runs in a test host, and is never
    /// linked into the app itself. The session identifier is Xcode's own mark
    /// of a test launch, checked as well in case XCTest ever loads later.
    static let isHostingTests =
        NSClassFromString("XCTestCase") != nil
        || ProcessInfo.processInfo.environment["XCTestSessionIdentifier"] != nil
}

/// A scene with no window: while the app hosts the tests, nothing of the real
/// app is built.
private struct TestHostApp: App {
    var body: some Scene {
        Settings { EmptyView() }
    }
}

extension UserDefaults {
    /// Where the app keeps what it stores in defaults. It is the app's own
    /// domain — except in a test run, where `.standard` is that same domain,
    /// the developer's real settings, because the tests run inside the app.
    /// A test run gets a scratch suite in its place, so a test that forgets
    /// to pass a store of its own still cannot reach the real one. Nothing in
    /// the app names `.standard`; it goes through here.
    ///
    /// The scratch suite is named by a path in the temporary folder, which
    /// keeps its file out of ~/Library/Preferences, where Magic Backup
    /// Machine's App Preferences source would back up anything named
    /// io.github.sevmorris.*.
    ///
    /// `nonisolated(unsafe)` because Swift 6 sees UserDefaults as non-Sendable,
    /// while Apple documents it as thread-safe; the reference is set once and
    /// never reassigned.
    nonisolated(unsafe) static let app: UserDefaults = AppLauncher.isHostingTests
        ? UserDefaults(suiteName: FileManager.default.temporaryDirectory
            .appendingPathComponent("io.github.sevmorris.KeyVault.tests").path)!
        : .standard
}

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
            // Disabled while the vault is locked: the window is showing the
            // locked screen, and a sheet presented over it would be one whose
            // Save cannot work.
            CommandGroup(replacing: .newItem) {
                Button("New Note") { viewModel.showAddNoteSheet = true }
                    .keyboardShortcut("n", modifiers: .command)
                    .disabled(viewModel.vaultIsLocked)
                Button("New API Key") { viewModel.showAddAPIKeySheet = true }
                    .keyboardShortcut("n", modifiers: [.command, .shift])
                    .disabled(viewModel.vaultIsLocked)
                Button("Add File…") { viewModel.showAddFileSheet = true }
                    .keyboardShortcut("n", modifiers: [.command, .option])
                    .disabled(viewModel.vaultIsLocked)
                Divider()
                Button("Generate Key…") { viewModel.showGenerateSheet = true }
                    .disabled(viewModel.vaultIsLocked)
                Button("Import Key…") { viewModel.showImportSheet = true }
                    .disabled(viewModel.vaultIsLocked)
            }

            CommandGroup(after: .saveItem) {
                Divider()
                Button("Organise Notes…") { viewModel.showBulkCategorise = true }
                    .keyboardShortcut("o", modifiers: [.command, .shift])
                    .disabled(viewModel.vaultIsLocked)
                Button("Back Up & Restore…") { viewModel.showBackupSheet = true }
                    .keyboardShortcut("b", modifiers: [.command, .shift])
                    .disabled(viewModel.vaultIsLocked)
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
                    .disabled(viewModel.vaultIsLocked)

                Divider()

                // One item that swings both ways rather than two that appear
                // and disappear. This is the way back in after cancelling the
                // prompt at launch, so it has to be somewhere you can find it
                // without knowing it exists.
                Button(viewModel.vaultIsLocked ? "Unlock Vault…" : "Lock Vault") {
                    if viewModel.vaultIsLocked {
                        viewModel.showVaultUnlock = true
                    } else {
                        viewModel.lockVault()
                    }
                }
                .keyboardShortcut("l", modifiers: [.command, .shift])
                .disabled(!viewModel.isVaultConfigured)
            }
        }
    }
}
