import SwiftUI

@main
struct KeyVaultApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .defaultSize(width: 960, height: 580)
        .commands {
            CommandGroup(after: .pasteboard) {
                Button("Copy Fingerprint") {
                    // Handled via KeyDetailView toolbar
                }
                .keyboardShortcut("f", modifiers: [.command, .shift])
            }
        }
    }
}
