

import Foundation

/// The protocol used in DNS servers.
public enum ProtocolDNSDelegate: String, Codable {
    case https
    public static let fallback: ProtocolDNSDelegate = .plain
    case tls
    case plain
    
}
