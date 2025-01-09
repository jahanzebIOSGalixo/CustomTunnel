

import Foundation
import CTunnelKitOpenVPNCore

public enum OpenVPNError: Error {
    case native(code: OpenVPNErrorCode)
    case pingTimeout
    case controlChannel(message: String)
    case malformedPushReply
    case noRouting
    case sessionMismatch
    case failedLinkWrite
    case badCredentials
    case serverShutdown
    case wrongControlDataPrefix
    case negotiationTimeout
    case missingSessionId
    case badKey
    case staleSession
    case serverCompression
}

extension Error {
    public var asNativeOpenVPNError: OpenVPNError? {
        let exception = self as NSError
        guard exception.domain == OpenVPNErrorDomain, let code = OpenVPNErrorCode(rawValue: exception.code) else {
            return nil
        }
        return .native(code: code)
    }
}
