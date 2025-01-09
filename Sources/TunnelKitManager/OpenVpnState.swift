

import Foundation

/// Status of a `VPN`.
public enum OpenVpnState: String {
    case disconnected
    case connected
    case disconnecting
    case connecting
}
