
import Foundation
import NetworkExtension

public struct MoreSetting {
    public var passwordReference: Data?
    public var disconnectsOnSleep = false
    public var onDemandRules: [NEOnDemandRule] = []
    #if !os(tvOS)
    public var killSwitch = false
    #endif
    public var userData: [String: Any]?
}


