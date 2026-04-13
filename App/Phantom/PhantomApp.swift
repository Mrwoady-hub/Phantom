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
        }

        Settings {
            SettingsView()
                .environmentObject(model)
                .environmentObject(engine)
        }

        if #available(macOS 13.0, *) {
            MenuBarExtra("Phantom", systemImage: model.status.menuBarSymbol) {
                MenuBarView()
                    .environmentObject(model)
                    .frame(width: 320)
                    .padding(12)
            }
            .menuBarExtraStyle(.window)
        }
    }
}
