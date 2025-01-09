

import Foundation

/// Encapsulates a proxy setting.
public struct GalixoServer:CustomStringConvertible ,Equatable, RawRepresentable,Codable  {

    public let address: String

    public let port: UInt16

    public init(_ address: String, _ port: UInt16) {
        self.address = address
        self.port = port
    }

    public var rawValue: String {
        return "\(address):\(port)"
    }

    public init?(rawValue: String) {
        let comps = rawValue.components(separatedBy: ":")
        guard comps.count == 2, let port = UInt16(comps[1]) else {
            return nil
        }
        self.init(comps[0], port)
    }

    public var description: String {
        return rawValue
    }
}
