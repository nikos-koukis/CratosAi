import JarvisUI
import SwiftUI

/// The iPhone app: everything lives in JarvisKit/JarvisUI; this is the shell.
@main
struct JarvisApp: App {
    @UIApplicationDelegateAdaptor(JarvisAppDelegate.self) private var delegate

    var body: some Scene {
        WindowGroup {
            RootView(model: delegate.model)
        }
    }
}
