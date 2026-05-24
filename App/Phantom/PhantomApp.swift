import SwiftUI

@main
struct PhantomApp: App {
    @StateObject private var model  = AppModel()
    @StateObject private var engine = PacketCaptureEngine()

    var body: some Scene {
        WindowGroup(id: "dashboard") {
            MainView()
                .environmentObject(model)
                .environmentObject(engine)
                .frame(minWidth: 1180, minHeight: 760)
                .task {
                    // Start the AI agent exactly once — after both AppModel and
                    // PacketCaptureEngine are fully initialised.  PhantomAIAgent.start()
                    // has its own `guard analysisTask == nil else { return }` so repeated
                    // calls (e.g. window focus/blur) are safe and are no-ops.
                    PhantomAIAgent.shared.start(appModel: model, engine: engine)
                }
        }

        Settings {
            SettingsView()
                .environmentObject(model)
                .environmentObject(engine)
        }

        MenuBarExtra("Phantom", systemImage: model.status.menuBarSymbol) {
            MenuBarView()
                .environmentObject(model)
                .frame(width: 320)
                .padding(12)
        }
        .menuBarExtraStyle(.window)
    }
}
