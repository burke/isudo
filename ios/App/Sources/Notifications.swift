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
