
import Foundation
import TunnelKitOpenVPNCore

public enum GalixoTunnelErrors: String, Error {
    case unexpectedReply
    case timeout
    case serverShutdown
    case lzo
    case exhaustedEndpoints
    case tlsInitialization
    case tlsHandshake
    case encryptionData
    case serverCompression
    case socketActivity
    case networkChanged
    case dnsFailure
    case authentication
    case routing
    case encryptionInitialization
    case linkError
    case gatewayUnattainable
    case tlsServerVerification
}

