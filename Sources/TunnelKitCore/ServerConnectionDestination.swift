

import Foundation
import __TunnelKitUtils

public struct ServerConnectionDestination: RawRepresentable, Codable, Equatable, CustomStringConvertible {
    public let proto: GalixoDestinationDelegate
    public let address: String
    private static let rx = NSRegularExpression("^([^\\s]+):(UDP[46]?|TCP[46]?):(\\d+)$")

    public init(_ address: String, _ proto: GalixoDestinationDelegate) {
        self.address = address
        self.proto = proto
    }
    
    public init?(rawValue: String) {
        let components = Self.rx.galixoGrouping(in: rawValue)
        guard components.count == 3 else {
            return nil
        }
        let address = components[0]
        guard let port = UInt16(components[2]) ,let socketType = TotalServerCount(rawValue: components[1]) else {
            return nil
        }

        self.init(address, GalixoDestinationDelegate(socketType, port))
    }

    private var isIPv6: Bool {
        var addr = in_addr()
        let result = address.withCString {
            inet_pton(AF_INET6, $0, &addr)
        }
        return result > 0
    }
    
    private var isIPv4: Bool {
        var addr = in_addr()
        let result = address.withCString {
            inet_pton(AF_INET, $0, &addr)
        }
        return result > 0
    }

    private var validNAme: Bool {
        !isIPv4 && !isIPv6
    }

    
    public func countNumber(_ length: Int) throws -> ServerConnectionDestination {
        guard validNAme else {
            return self
        }
        let prefix = try SecureRandom.data(length: length)
        let prefixedAddress = "\(prefix.toHex()).\(address)"
        return ServerConnectionDestination(prefixedAddress, proto)
    }

    public var rawValue: String {
        "\(address):\(proto.socketType.rawValue):\(proto.port)"
    }

    // MARK: CustomStringConvertible

    public var description: String {
        "\(address.maskedDescription):\(proto.rawValue)"
    }
}


