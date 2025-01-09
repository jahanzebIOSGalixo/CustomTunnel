

import Foundation
import CTunnelKitOpenVPNCore

public enum VpnErrors: Error {
    case negotiationTimeout
    case missingSessionId
    case sessionMismatch
    case badKey
    case controlChannel(message: String)
    case wrongControlDataPrefix
    case badCredentials
    case malformedPushReply
    case failedLinkWrite
    case pingTimeout
    case staleSession
    case serverCompression
    case noRouting
    case serverShutdown
    case native(code: OpenVPNErrorCode)
}


extension Error {
    public var asNativeOpenVPNError: VpnErrors? {
        let nativeError = self as NSError
        guard nativeError.domain == OpenVPNErrorDomain, let code = OpenVPNErrorCode(rawValue: nativeError.code) else {
            return nil
        }
        return .native(code: code)
    }
}
