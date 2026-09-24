import Foundation

/// Which APNs environment this build's device token belongs to.
enum PushEnvironment {
    /// Builds from Xcode (and the simulator) use the sandbox; TestFlight and
    /// App Store builds use production. The build's provisioning profile says
    /// which: App Store builds have none, development ones say "development".
    static var isSandbox: Bool {
        #if targetEnvironment(simulator)
            return true
        #else
            guard let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
                let data = try? Data(contentsOf: url),
                let start = data.range(of: Data("<plist".utf8)),
                let end = data.range(of: Data("</plist>".utf8), in: start.upperBound..<data.endIndex),
                let plist = try? PropertyListSerialization.propertyList(
                    from: data[start.lowerBound..<end.upperBound], format: nil) as? [String: Any],
                let entitlements = plist["Entitlements"] as? [String: Any]
            else {
                return false
            }
            return entitlements["aps-environment"] as? String == "development"
        #endif
    }
}
