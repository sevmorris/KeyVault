import AppKit
import Foundation

/// Notices when the app has been left alone, so the vault can shut itself.
///
/// Idleness is measured in events delivered to *this* app, which is both the
/// cheapest thing to observe and the right definition: a local monitor sees
/// nothing while you are working in another window, so switching away starts
/// the clock, and coming back to KeyVault stops it.
@MainActor
final class IdleWatcher {
    /// How long the app may go untouched, or nil for never. Asked on every
    /// tick rather than captured once, so changing it in Settings takes effect
    /// without the watcher having to be torn down and rebuilt.
    var idleLimit: () -> TimeInterval? = { nil }
    var onIdle: () -> Void = {}

    /// Coarse on purpose. The question is whether someone walked away, and
    /// asking it four times a minute is precise enough for that while costing
    /// nothing on a Mac that is idle by definition when it matters.
    private static let tick: TimeInterval = 15

    private var monitor: Any?
    private var timer: Timer?
    private var lastActivity = Date()

    func start() {
        guard monitor == nil else { return }

        monitor = NSEvent.addLocalMonitorForEvents(
            matching: [.keyDown, .flagsChanged, .leftMouseDown, .rightMouseDown,
                       .otherMouseDown, .scrollWheel]
        ) { [weak self] event in
            self?.lastActivity = Date()
            // Returned unchanged: a monitor that swallowed events would stop
            // the app responding to the very keystrokes it is counting.
            return event
        }

        timer = Timer.scheduledTimer(withTimeInterval: Self.tick, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.check() }
        }
    }

    /// Restart the countdown — after an unlock, so a vault just opened is not
    /// measured against however long it sat closed.
    func reset() {
        lastActivity = Date()
    }

    private func check() {
        guard let limit = idleLimit(), limit > 0 else { return }
        guard Date().timeIntervalSince(lastActivity) >= limit else { return }
        onIdle()
    }

    deinit {
        timer?.invalidate()
        if let monitor { NSEvent.removeMonitor(monitor) }
    }
}
