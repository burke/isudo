import UIKit
import UserNotifications

/// Push notifications tell the app a request is waiting. They never carry
/// the request, and nothing can be approved from one: the card, and Face ID,
/// are in the app.
enum Notifications {
    static let category = "ISUDO_REQUEST"

    /// Which Apple push environment this build's device tokens belong to.
    static var environment: String {
        #if DEBUG
        "sandbox"
        #else
        "production"
        #endif
    }

    static func registerCategory() {
        let category = UNNotificationCategory(identifier: category, actions: [], intentIdentifiers: [])
        UNUserNotificationCenter.current().setNotificationCategories([category])
    }

    /// The request a notification is about, if it is one of ours.
    static func requestID(in userInfo: [AnyHashable: Any]) -> String? {
        (userInfo["isudo"] as? [String: Any])?["r"] as? String
    }

    /// Whether a push says a request has been answered, and which.
    static func settledRequestID(in userInfo: [AnyHashable: Any]) -> String? {
        guard let fields = userInfo["isudo"] as? [String: Any], fields["done"] as? Bool == true else { return nil }
        return fields["r"] as? String
    }

    /// Takes down the notification about a request that has been answered.
    /// Clearing it here clears it on the watch too, where it was mirrored.
    static func clear(requestID: String) {
        let center = UNUserNotificationCenter.current()
        Task {
            let stale = await center.deliveredNotifications()
                .filter { Self.requestID(in: $0.request.content.userInfo) == requestID }
                .map(\.request.identifier)
            if !stale.isEmpty {
                center.removeDeliveredNotifications(withIdentifiers: stale)
            }
        }
    }

    @MainActor
    static func requestPermission() {
        Task {
            let center = UNUserNotificationCenter.current()
            guard (try? await center.requestAuthorization(options: [.alert, .sound, .badge])) == true else { return }
            UIApplication.shared.registerForRemoteNotifications()
        }
    }
}

final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    /// Set by the app once the model exists.
    @MainActor static var model: AppModel?

    func application(
        _ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        Notifications.registerCategory()
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let token = deviceToken.map { String(format: "%02x", $0) }.joined()
        Task { @MainActor in Self.model?.setDeviceToken(token) }
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        // Without push the app still works whenever it is open.
    }

    /// A quiet push: the relay saying a request has been answered, here or
    /// on the watch, so that nothing goes on asking about it.
    func application(
        _ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable: Any]
    ) async -> UIBackgroundFetchResult {
        guard let requestID = Notifications.settledRequestID(in: userInfo) else { return .noData }
        await MainActor.run { Self.model?.settled(requestID: requestID) }
        Notifications.clear(requestID: requestID)
        return .newData
    }

    /// A push arrived while the app is in front: the card is about to
    /// appear, so no banner is needed.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        await Self.refresh()
        return []
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse
    ) async {
        await Self.refresh()
    }

    @MainActor
    private static func refresh() async {
        await model?.refresh()
    }
}
