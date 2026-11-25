import IsudoKit
import SwiftUI
import UserNotifications
import WatchKit

@main
struct IsudoWatchApp: App {
    @WKApplicationDelegateAdaptor private var delegate: WatchAppDelegate
    @Environment(\.scenePhase) private var scenePhase
    private let model = WatchModel.shared

    init() {
        #if DEBUG
        if let fixture = UserDefaults.standard.string(forKey: "fixture") {
            model.loadFixture(named: fixture)
        }
        #endif
    }

    var body: some Scene {
        WindowGroup {
            WatchHomeView()
                .environment(model)
                .onChange(of: scenePhase, initial: true) { _, phase in
                    if phase == .active {
                        model.startPolling()
                    } else {
                        model.stopPolling()
                    }
                }
        }
        // The notification about a request shows the request itself, with
        // the same controls as the app.
        WKNotificationScene(controller: RequestNotificationController.self, category: "ISUDO_REQUEST")
    }
}

final class WatchAppDelegate: NSObject, WKApplicationDelegate, UNUserNotificationCenterDelegate {
    func applicationDidFinishLaunching() {
        UNUserNotificationCenter.current().delegate = self
        let category = UNNotificationCategory(identifier: "ISUDO_REQUEST", actions: [], intentIdentifiers: [])
        UNUserNotificationCenter.current().setNotificationCategories([category])
        Task { @MainActor in WatchModel.shared.start() }
    }

    /// A notification arrived while the app is in front: the request is
    /// about to appear in it, so a banner would only be in the way.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        let userInfo = Payload(notification.request.content.userInfo)
        await MainActor.run { _ = WatchModel.shared.received(push: userInfo.fields) }
        return []
    }

    /// The notification was tapped: the app opens on the request.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse
    ) async {
        let userInfo = Payload(response.notification.request.content.userInfo)
        await MainActor.run { _ = WatchModel.shared.received(push: userInfo.fields) }
    }
}

/// A notification's payload, carried across to the main actor. It is
/// property-list values, which do not change once delivered.
struct Payload: @unchecked Sendable {
    let fields: [AnyHashable: Any]

    init(_ fields: [AnyHashable: Any]) {
        self.fields = fields
    }
}

/// Shows a request inside its notification, so that raising the wrist is
/// enough to read it and answer.
final class RequestNotificationController: WKUserNotificationHostingController<RequestNotificationView> {
    private var requestID: Data?

    override class var isInteractive: Bool { true }

    override var body: RequestNotificationView {
        RequestNotificationView(requestID: requestID)
    }

    override func didReceive(_ notification: UNNotification) {
        requestID = WatchModel.shared.received(push: notification.request.content.userInfo)?.id
    }
}

struct RequestNotificationView: View {
    let requestID: Data?

    var body: some View {
        let model = WatchModel.shared
        if let request = model.requests.first(where: { $0.id == requestID }) {
            RequestView(request: request).environment(model)
        } else {
            // Too large to ride in a notification, or not sealed to this
            // watch: nothing can be shown or approved from here.
            VStack(alignment: .leading, spacing: 6) {
                Label("Approval requested", systemImage: "desktopcomputer").font(.headline)
                Text("Open isudo to see it, or review it on your iPhone.").font(.footnote).foregroundStyle(.secondary)
            }
        }
    }
}
