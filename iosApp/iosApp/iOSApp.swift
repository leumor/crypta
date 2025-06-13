import SwiftUI
import ComposeApp

@main
struct iOSApp: App {
    @Environment(\.scenePhase) private var scenePhase

    init() {
        AppScopeKt.startAppScope()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .onChange(of: scenePhase) { newPhase in
            if newPhase == .background || newPhase == .inactive {
                AppScopeKt.cancelAppScope()
            }
        }
    }
}