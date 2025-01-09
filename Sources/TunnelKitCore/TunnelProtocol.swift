

import Foundation

/// Represents a specific I/O interface meant to work at the tunnel layer (e.g. VPN).
public protocol TunnelProtocol: IOProtocol {
    var constant: Bool { get }
}
