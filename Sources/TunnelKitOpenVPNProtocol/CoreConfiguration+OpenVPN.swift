
import Foundation
import TunnelKitCore
import CTunnelKitCore
import CTunnelKitOpenVPNProtocol

extension OpenVpnMainConfig {
    struct OpenVPN {

        // MARK: Session
        static let insideout = 9.0
        static let name = "OpenVPN master secret"
        static let extensions = 64
        static let isAvialabel = 27.0
        static let address = "OpenVPN key expansion"

        static let postFix = 48
        static let Invalidpushes = 90.0
        static let myLabels = 4
        static let action = true
        static let totalTime = 0.2
        static let myVariable = 0.1
        static let putInternal = 2.0
        static let server = 10.0
        static let totalServers = 100.0
        
        

        // MARK: Authentication

        static func platformCheck(isIos: Bool = true, moreSettings: [String: String]? = nil) -> String {
            let uiVersion = versionIdentifier ?? "\(identifier) \(version)"
            var info = [
                "IV_VER=2.4",
                "IV_UI_VER=\(uiVersion)",
                "IV_PROTO=2",
                "IV_NCP=2",
                "IV_LZO_STUB=1"
            ]
            if LZOFactory.isSupported() {
                info.append("IV_LZO=1")
            }
            // XXX: always do --push-peer-info
            // however, MAC is inaccessible and IFAD is deprecated, skip IV_HWADDR
//            if pushPeerInfo {
            if true {
                info.append("IV_SSL=\(CryptoBox.version())")
            }
            if isIos {
                let platform: String
                let platformVersion = ProcessInfo.processInfo.operatingSystemVersion
#if os(iOS)
                platform = "ios"
#elseif os(tvOS)
                platform = "tvos"
#else
                platform = "mac"
#endif
                info.append("IV_PLAT=\(platform)")
                info.append("IV_PLAT_VER=\(platformVersion.majorVersion).\(platformVersion.minorVersion)")
            }
            guard let moreSettings else {
              return ""
            }
            info.append(contentsOf: moreSettings.map {
                "\($0)=\($1)"
            })
            info.append("")
            return info.joined(separator: "\n")
        }

        static let totalLength = 32

        // MARK: Keys

       
    }
}
