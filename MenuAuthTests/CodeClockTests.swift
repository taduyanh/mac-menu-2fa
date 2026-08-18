import AppKit
import Foundation
import Testing

@testable import MenuAuth

/// The clock is the whole footprint story, so its start/stop contract is
/// asserted rather than assumed.
@Suite("Code clock", .serialized)
@MainActor
struct CodeClockTests {
    @Test("Starting and stopping flips the running flag")
    func startStop() {
        let clock = CodeClock()
        #expect(!clock.isRunning)

        clock.start()
        #expect(clock.isRunning)

        clock.stop()
        #expect(!clock.isRunning)
    }

    /// A second `start()` must not leave a second timer running — that would
    /// double the wakeup rate for the rest of the session.
    @Test("Starting twice is idempotent")
    func startIsIdempotent() {
        let clock = CodeClock()
        clock.start()
        clock.start()
        clock.start()

        clock.stop()
        #expect(!clock.isRunning)
    }

    @Test("Stopping without starting is safe")
    func stopWithoutStart() {
        let clock = CodeClock()
        clock.stop()
        #expect(!clock.isRunning)
    }

    @Test("Starting adopts the injected time source")
    func startAdoptsInjectedTime() {
        let clock = CodeClock()
        let fixed = Date(timeIntervalSince1970: 1_699_999_980)
        clock.nowProvider = { fixed }

        clock.start()
        defer { clock.stop() }
        #expect(clock.tick == fixed)
    }

    @Test("Binding to app activation is idempotent")
    func activationBindingIsIdempotent() {
        let clock = CodeClock()
        clock.bindToAppActivation()
        clock.bindToAppActivation()
        clock.start()

        // Resigning active must stop the clock even though the view never
        // disappeared — the belt-and-braces path.
        NotificationCenter.default.post(
            name: NSApplication.didResignActiveNotification,
            object: nil
        )
        #expect(!clock.isRunning)
    }

    @Test("Resigning active stops a running clock")
    func resignActiveStops() {
        let clock = CodeClock()
        clock.bindToAppActivation()
        clock.start()
        #expect(clock.isRunning)

        NotificationCenter.default.post(
            name: NSApplication.didResignActiveNotification,
            object: nil
        )
        #expect(!clock.isRunning)

        NotificationCenter.default.post(
            name: NSApplication.didBecomeActiveNotification,
            object: nil
        )
        #expect(clock.isRunning)
        clock.stop()
    }

    /// Proves the timer really fires, so "one tick per second" is not just a
    /// schedule that never runs.
    @Test("A running clock ticks", .timeLimit(.minutes(1)))
    func clockTicks() async throws {
        let clock = CodeClock()
        clock.start()
        defer { clock.stop() }

        let first = clock.tick
        try await Task.sleep(for: .milliseconds(2500))
        #expect(clock.tick > first)
    }

    /// And the converse: a stopped clock must be genuinely inert.
    @Test("A stopped clock does not tick", .timeLimit(.minutes(1)))
    func stoppedClockIsInert() async throws {
        let clock = CodeClock()
        clock.start()
        try await Task.sleep(for: .milliseconds(1200))
        clock.stop()

        let afterStop = clock.tick
        try await Task.sleep(for: .milliseconds(2500))
        #expect(clock.tick == afterStop)
    }
}
