import AppKit

/// Quitting that works while a sheet is open.
///
/// AppKit will not terminate an app while any of its windows has a sheet
/// attached: `terminate(_:)` returns without asking the delegate, without a
/// beep, and a quit Apple Event is answered "User canceled" (-128). KeyVault
/// opens with the passphrase prompt as a sheet, so ⌘Q did nothing at launch,
/// and the Dock's Quit, logging out and restarting were all refused for as
/// long as that prompt, or any other sheet, alert or file panel, was up.
///
/// Closing the sheets first is not enough. `endSheet` takes one off, but its
/// SwiftUI binding is still true, and `terminate` itself redraws the window,
/// so SwiftUI puts the sheet straight back before AppKit looks (seen with the
/// passphrase prompt, 2026-11-23). Clearing every binding would need each
/// view's own state, and a sheet added later would quietly break Quit again.
///
/// So AppKit is asked first, as any app would. A `terminate` that goes ahead
/// never returns; one that returns has been refused, and the only refusal
/// this app can meet is an open sheet, since nothing implements
/// `applicationShouldTerminate`. Then KeyVault finishes the quit itself:
/// the notice `terminate` would have posted, and exit. Whatever the sheet
/// held is discarded, an edit in progress included — the owner's choice
/// (2026-11-23) over a quit that refuses. The vault key goes with the
/// process, as it does on any quit.
@MainActor
enum AppQuit {
    static func quit() {
        NSApp.terminate(nil)
        NotificationCenter.default.post(name: NSApplication.willTerminateNotification,
                                        object: NSApp)
        exit(0)
    }
}

/// Takes the quit Apple Event — the Dock's Quit, logging out, restarting,
/// `osascript -e 'quit app "KeyVault"'` — away from AppKit's own handler,
/// which would refuse it while a sheet is open. The menu's Quit is a command
/// of the app's own (`KeyVaultApp`), since it calls `terminate(_:)` directly
/// and never becomes an Apple Event.
final class AppDelegate: NSObject, NSApplicationDelegate {
    /// Before launch finishes, so no quit can arrive while AppKit's handler is
    /// still the one installed.
    func applicationWillFinishLaunching(_ notification: Notification) {
        NSAppleEventManager.shared().setEventHandler(
            self,
            andSelector: #selector(handleQuit(_:withReplyEvent:)),
            forEventClass: AEEventClass(kCoreEventClass),
            andEventID: AEEventID(kAEQuitApplication)
        )
    }

    /// Apple Events are delivered on the main thread.
    @objc private func handleQuit(_ event: NSAppleEventDescriptor,
                                  withReplyEvent reply: NSAppleEventDescriptor) {
        MainActor.assumeIsolated { AppQuit.quit() }
    }
}
