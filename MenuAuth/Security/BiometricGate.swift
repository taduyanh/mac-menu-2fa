import AppKit
import Foundation
import LocalAuthentication
import Observation

/// Owns "is the user currently allowed to see codes?".
///
/// One `LAContext` is authenticated and then reused, so unlocking once covers a
/// burst of Keychain reads instead of prompting per account. The context is
/// dropped — and the vault's plaintext cache cleared — when the session lapses.
@Observable
final class BiometricGate {
    /// How the unlock is enforced, which depends on how the app was signed.
    /// Surfaced in Settings so the app never overstates its own security.
    enum Enforcement: Equatable {
        /// The Keychain itself refuses to hand over a secret without Touch ID.
        case keychainEnforced
        /// The Keychain releases secrets to this app freely; MenuAuth asks for
        /// Touch ID before revealing them. Protects against someone at your
        /// unlocked Mac, not against code running as you.
        case appEnforced
        /// No biometric or password policy is available on this Mac.
        case unavailable

        var summary: String {
            switch self {
            case .keychainEnforced:
                "Secrets are sealed by the Keychain and released only after Touch ID."
            case .appEnforced:
                "Secrets are stored in your login Keychain. MenuAuth asks for Touch ID "
                    + "before showing codes."
            case .unavailable:
                "No Touch ID or password policy is available, so codes are shown "
                    + "whenever the panel is open."
            }
        }
    }

    private(set) var isUnlocked: Bool
    private(set) var lastErrorMessage: String?
    let enforcement: Enforcement

    /// How long an unlock survives without interaction. The Keychain's own
    /// context reuse caps out at five minutes, so anything longer is carried by
    /// holding decrypted secrets in memory until this deadline.
    var idleTimeout: TimeInterval {
        didSet { scheduleRelock() }
    }

    private var context: LAContext?
    /// A single one-shot timer, alive only while unlocked — never a poll.
    private var relockTask: Task<Void, Never>?
    private var observers: [any NSObjectProtocol] = []

    /// Called when the session lapses so the vault can drop plaintext secrets.
    var onLock: (() -> Void)?

    init(enforcement: Enforcement, idleTimeout: TimeInterval = 300) {
        self.enforcement = enforcement
        self.idleTimeout = idleTimeout
        // With no policy available there is nothing to unlock, so codes are
        // always visible rather than permanently hidden.
        isUnlocked = enforcement == .unavailable
        observeLockEvents()
    }

    isolated deinit {
        relockTask?.cancel()
        for observer in observers {
            DistributedNotificationCenter.default().removeObserver(observer)
            NSWorkspace.shared.notificationCenter.removeObserver(observer)
        }
    }

    /// An authenticated context to hand to the Keychain, when the Keychain is
    /// the thing doing the enforcing.
    var authenticatedContext: LAContext? {
        enforcement == .keychainEnforced && isUnlocked ? context : nil
    }

    @discardableResult
    func unlock(reason: String = "reveal your authentication codes") async -> Bool {
        guard enforcement != .unavailable else { return true }
        if isUnlocked {
            noteActivity()
            return true
        }

        let context = LAContext()
        // Lets one authentication cover the burst of Keychain reads that
        // follows, instead of prompting once per account.
        context.touchIDAuthenticationAllowableReuseDuration =
            LATouchIDAuthenticationMaximumAllowableReuseDuration
        context.localizedCancelTitle = "Cancel"

        do {
            let success = try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            )
            guard success else {
                lastErrorMessage = "Authentication failed."
                return false
            }
            self.context = context
            isUnlocked = true
            lastErrorMessage = nil
            scheduleRelock()
            return true
        } catch let error as LAError where error.code == .userCancel
            || error.code == .appCancel || error.code == .systemCancel {
            // Cancelling is a choice, not an error worth shouting about.
            lastErrorMessage = nil
            return false
        } catch {
            lastErrorMessage = error.localizedDescription
            return false
        }
    }

    func lock() {
        relockTask?.cancel()
        relockTask = nil
        // Invalidating tears down any credential the context is holding.
        context?.invalidate()
        context = nil
        if enforcement != .unavailable {
            isUnlocked = false
        }
        onLock?()
    }

    /// Pushes the re-lock deadline out. Called when the panel is opened or a
    /// code is copied, so the gate measures idleness rather than wall time.
    func noteActivity() {
        guard isUnlocked, enforcement != .unavailable else { return }
        scheduleRelock()
    }

    private func scheduleRelock() {
        relockTask?.cancel()
        guard isUnlocked, enforcement != .unavailable, idleTimeout > 0 else { return }

        let timeout = idleTimeout
        relockTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(timeout))
            guard !Task.isCancelled else { return }
            self?.lock()
        }
    }

    /// Locking the screen or closing the lid should drop the session
    /// immediately rather than wait out the idle timer.
    private func observeLockEvents() {
        let distributed = DistributedNotificationCenter.default()
        observers.append(
            distributed.addObserver(
                forName: Notification.Name("com.apple.screenIsLocked"),
                object: nil,
                queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.lock() }
            }
        )

        let workspace = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification] {
            observers.append(
                workspace.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                    MainActor.assumeIsolated { self?.lock() }
                }
            )
        }
    }
}
