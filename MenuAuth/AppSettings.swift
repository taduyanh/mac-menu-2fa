import Foundation
import Observation
import ServiceManagement

/// User preferences, backed by `UserDefaults`, plus the login-item toggle.
@Observable
final class AppSettings {
    enum Key {
        static let idleTimeout = "idleTimeoutSeconds"
    }

    /// Offered values for the re-lock delay, in seconds.
    static let idleTimeoutChoices: [TimeInterval] = [60, 300, 900, 1800, 0]

    @ObservationIgnored private let defaults: UserDefaults

    var idleTimeout: TimeInterval {
        didSet { defaults.set(idleTimeout, forKey: Key.idleTimeout) }
    }

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        // `UserDefaults` is a plist anyone can edit, and a negative or absurd
        // value would silently disable re-locking, so only offered choices are
        // honoured.
        let stored = defaults.object(forKey: Key.idleTimeout) as? Double
        idleTimeout = stored.flatMap { Self.idleTimeoutChoices.contains($0) ? $0 : nil } ?? 300
    }

    static func describeTimeout(_ seconds: TimeInterval) -> String {
        switch seconds {
        case 0: "Never"
        case ..<3600: "\(Int(seconds / 60)) min"
        default: "\(Int(seconds / 3600)) hr"
        }
    }

    // MARK: - Launch at login

    var launchesAtLogin: Bool {
        SMAppService.mainApp.status == .enabled
    }

    /// Returns a message when the change could not be applied — most often
    /// because the app is being run from DerivedData rather than /Applications.
    func setLaunchAtLogin(_ enabled: Bool) -> String? {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            return nil
        } catch {
            return "Couldn't update the login item: \(error.localizedDescription). "
                + "Move MenuAuth to /Applications and try again."
        }
    }
}
