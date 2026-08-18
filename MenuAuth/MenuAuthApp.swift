import SwiftUI

@main
struct MenuAuthApp: App {
    @State private var store: AccountStore
    @State private var settings: AppSettings
    /// Lives at app scope, not in the import view: dismissing the panel to go
    /// swipe to the next export QR must not discard a half-scanned batch.
    @State private var importSession = ImportSession()

    init() {
        let settings = AppSettings()
        let vault = SecretVault()
        let gate = BiometricGate(
            enforcement: vault.enforcement,
            idleTimeout: settings.idleTimeout
        )
        _settings = State(initialValue: settings)
        _store = State(
            initialValue: AccountStore(
                metadata: .makeDefault(),
                vault: vault,
                gate: gate
            )
        )
    }

    var body: some Scene {
        MenuBarExtra("MenuAuth", systemImage: "lock.rotation") {
            MenuPanel()
                .environment(store)
                .environment(settings)
                .environment(importSession)
        }
        // `.window` gives a real panel that renders on demand and picks up the
        // system material, rather than a menu of rows.
        .menuBarExtraStyle(.window)
    }
}
