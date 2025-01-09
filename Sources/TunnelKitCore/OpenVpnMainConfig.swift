

import Foundation


public class OpenVpnMainConfig {

    public static let identifier = "com.algoritmico.TunnelKit"

    /// Library version as seen in `Info.plist`.
    public static let version: String = {
        let bundle = Bundle(for: OpenVpnMainConfig.self)
        guard let info = bundle.infoDictionary else {
            return ""
        }
        return info["CFBundleShortVersionString"] as? String ?? ""
    }()
    public static var masksPrivateData = true

    public static var versionIdentifier: String?

    public static let logsSensitiveData = false
}

extension CustomStringConvertible {

    public var maskedDescription: String {
        guard OpenVpnMainConfig.masksPrivateData else {
            return description
        }

        return "<masked>"
    }
}
