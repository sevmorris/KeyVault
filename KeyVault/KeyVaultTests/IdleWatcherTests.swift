import AppKit
import XCTest
@testable import KeyVault

/// The notifications are posted in-process, on the same centres the system
/// uses, so these exercise the watcher's own wiring without sleeping the Mac.
/// A hosted test run builds no view model, so nothing real locks.
@MainActor
final class IdleWatcherTests: XCTestCase {

    private func awayCount(after post: () -> Void) -> Int {
        let watcher = IdleWatcher()
        var count = 0
        watcher.onAway = { count += 1 }
        watcher.start()
        post()
        return count
    }

    func testSleepCallsOnAway() {
        XCTAssertEqual(awayCount {
            NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.willSleepNotification, object: nil)
        }, 1)
    }

    func testSwitchingUserCallsOnAway() {
        XCTAssertEqual(awayCount {
            NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.sessionDidResignActiveNotification,
                                                       object: nil)
        }, 1)
    }

    /// Never fires on its own: being away is not the same as idle, and the
    /// idle limit is nil by default.
    func testAwayIgnoresTheIdleLimit() {
        let watcher = IdleWatcher()
        var idle = 0, away = 0
        watcher.onIdle = { idle += 1 }
        watcher.onAway = { away += 1 }
        watcher.start()
        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.willSleepNotification, object: nil)
        XCTAssertEqual(away, 1)
        XCTAssertEqual(idle, 0)
    }

    /// A released watcher calls nothing, so no lock outlives its owner.
    func testAReleasedWatcherStopsListening() {
        var count = 0
        do {
            let watcher = IdleWatcher()
            watcher.onAway = { count += 1 }
            watcher.start()
        }
        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.willSleepNotification, object: nil)
        XCTAssertEqual(count, 0)
    }
}
