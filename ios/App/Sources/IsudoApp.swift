import SwiftUI

@main
struct IsudoApp: App {
    @UIApplicationDelegateAdaptor private var appDelegate: AppDelegate
    @Environment(\.scenePhase) private var scenePhase
    @State private var model: AppModel
    private let appearance: ColorScheme?

    init() {
        let launch = LaunchOptions()
        appearance = launch.appearance
        #if DEBUG
        if let fixture = launch.fixture {
            _model = State(initialValue: AppModel(fixture: fixture))
            return
        }
        #endif
        _model = State(initialValue: AppModel())
    }

    var body: some Scene {
        WindowGroup {
            HomeView()
                .environment(model)
                .preferredColorScheme(appearance)
                .onOpenURL { model.handle(url: $0) }
                .onAppear {
                    AppDelegate.model = model
                    model.startWatchLink()
                }
                .onChange(of: scenePhase, initial: true) { _, phase in
                    if phase == .active {
                        model.startPolling()
                    } else {
                        model.stopPolling()
                    }
                }
        }
    }
}

/// Launch arguments understood by debug builds, for screenshots:
/// `-fixture NAME` and `-appearance light|dark`.
struct LaunchOptions {
    var appearance: ColorScheme?

    init() {
        switch UserDefaults.standard.string(forKey: "appearance") {
        case "dark": appearance = .dark
        case "light": appearance = .light
        default: appearance = nil
        }
    }

    #if DEBUG
    var fixture: Fixture? {
        UserDefaults.standard.string(forKey: "fixture").flatMap(Fixture.init(named:))
    }
    #endif
}
