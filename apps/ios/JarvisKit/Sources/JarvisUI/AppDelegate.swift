#if os(iOS)
    import JarvisKit
    import UIKit
    import UserNotifications
    import os

    /// The app delegate: it owns the model and connects it to APNs and to
    /// notification taps.
    @MainActor
    public final class JarvisAppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
        public let model = AppModel()
        private let log = Logger(subsystem: "ai.cratos.jarvis", category: "push")

        public func application(
            _ application: UIApplication,
            didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
        ) -> Bool {
            UNUserNotificationCenter.current().delegate = self
            return true
        }

        public func application(
            _ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
        ) {
            Task { await model.pushTokenReceived(deviceToken) }
        }

        public func application(
            _ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error
        ) {
            log.warning("APNs registration failed: \(String(describing: error), privacy: .public)")
        }

        /// Show notifications while the app is open, too.
        public nonisolated func userNotificationCenter(
            _ center: UNUserNotificationCenter, willPresent notification: UNNotification
        ) async -> UNNotificationPresentationOptions {
            [.banner, .list, .sound]
        }

        /// A tap on a notification opens its tab.
        public nonisolated func userNotificationCenter(
            _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse
        ) async {
            let data = response.notification.request.content.userInfo["jarvis"] as? [String: String]
            let kind = data?["kind"] ?? ""
            await model.openNotification(kind: kind)
        }
    }
#endif
