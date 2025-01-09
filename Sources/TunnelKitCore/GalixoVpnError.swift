

import Foundation

/// Errors returned by Core library.
public enum GalixoVpnError: Error {
    case dnsResolver(_ error: HostError)
    case secureRandom(_ error: ServerErrorss)
    
}
