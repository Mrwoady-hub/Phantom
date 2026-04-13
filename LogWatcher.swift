import Foundation

/// Fires `onChange` on the main actor at a regular interval.
///
/// THREADING:
/// `Timer.scheduledTimer` closures are marked `@Sendable` by the Swift runtime.
/// A `@Sendable` closure cannot directly reference `@MainActor`-isolated properties
/// (like `onChange`) — the compiler rejects it in Swift 6 strict concurrency mode.
///
/// Fix: create a `Task { @MainActor in ... }` inside the timer closure.
/// This performs a proper actor hop rather than a direct isolated-property access,
/// which is both correct and compiler-clean.
@MainActor
final class LogWatcher {
    var onChange: (() -> Void)?
    private var timer: Timer?

    func startWatching() {
        stopWatching()
        let t = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { _ in
            // @Sendable closure — cannot reference @MainActor-isolated 'onChange' directly.
            // Task { @MainActor } performs the required hop.
            Task { @MainActor [weak self] in
                self?.onChange?()
            }
        }
        // .common RunLoop mode: timer fires during UI event tracking (scroll, drag),
        // not only during the default idle mode.
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    func stopWatching() {
        timer?.invalidate()
        timer = nil
    }

    deinit {
        timer?.invalidate()
    }
}
