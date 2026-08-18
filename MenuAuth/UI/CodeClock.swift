import AppKit
import Foundation
import Observation

/// The app's only periodic timer.
///
/// It is started when the menu bar panel appears and invalidated when it
/// disappears, so a closed panel means genuinely zero scheduled work — no
/// wakeups, no CPU. That is the whole point of the design: the app is resident
/// all day but only *runs* in the seconds you are looking at it.
///
/// The 1 Hz tick drives the countdown ring only. Codes are recomputed by
/// `AccountStore` when the RFC 6238 time step changes, which is once per 30
/// seconds per account — not once per tick.
@Observable
final class CodeClock {
    /// Current time, quantised to whole seconds. Views observe this.
    private(set) var tick: Date = Date()
    private(set) var isRunning = false

    @ObservationIgnored private var timer: DispatchSourceTimer?
    @ObservationIgnored private var activationObservers: [any NSObjectProtocol] = []

    /// Overridable so tests can drive time without waiting on a real clock.
    @ObservationIgnored var nowProvider: () -> Date = { Date() }

    /// Ties the clock to app activation as well as to the panel's view
    /// lifecycle.
    ///
    /// `onAppear`/`onDisappear` are the primary hinge, but they depend on
    /// SwiftUI actually tearing down `MenuBarExtra`'s content when the panel
    /// closes — an implementation detail, not a documented guarantee. For an
    /// agent app with no windows, the *only* thing that makes it active is the
    /// panel opening, and dismissing the panel resigns active. Observing that
    /// makes "nothing runs while closed" hold either way.
    func bindToAppActivation() {
        guard activationObservers.isEmpty else { return }
        let center = NotificationCenter.default

        activationObservers.append(
            center.addObserver(
                forName: NSApplication.didResignActiveNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.stop() }
            }
        )
        activationObservers.append(
            center.addObserver(
                forName: NSApplication.didBecomeActiveNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.start() }
            }
        )
    }

    func start() {
        guard timer == nil else { return }
        tick = nowProvider()
        isRunning = true

        let timer = DispatchSource.makeTimerSource(queue: .main)
        // Align to the next whole second so the countdown changes when the
        // displayed number changes, rather than drifting a fraction late.
        let now = nowProvider().timeIntervalSince1970
        let untilNextSecond = 1 - (now - now.rounded(.down))

        timer.schedule(
            deadline: .now() + untilNextSecond,
            repeating: .seconds(1),
            // Lets the kernel coalesce this wakeup with others already
            // scheduled, which is what keeps idle power cost near zero.
            leeway: .milliseconds(150)
        )
        timer.setEventHandler { [weak self] in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.tick = self.nowProvider()
            }
        }
        timer.resume()
        self.timer = timer
    }

    func stop() {
        timer?.cancel()
        timer = nil
        isRunning = false
    }

    /// Isolated so it can touch `timer`. A resumed `DispatchSourceTimer` that
    /// is deallocated without being cancelled traps in libdispatch, so this is
    /// load-bearing rather than tidiness.
    isolated deinit {
        timer?.cancel()
        for observer in activationObservers {
            NotificationCenter.default.removeObserver(observer)
        }
    }
}
