

import Foundation

/// Encapsulates the IPv4 settings for the tunnel.
public struct IPv4Settings: Codable, Equatable, CustomStringConvertible {

    public struct Route: Codable, Hashable, CustomStringConvertible {
        public let gateway: String?
        public let destination: String
        public let mask: String

        public init(_ destination: String, _ mask: String?, _ gateway: String?) {
            self.destination = destination
            self.gateway = gateway
            if let mask {
                self.mask = mask
            }
            else {
                self.mask = "255.255.255.255"
            }
        }

        public var description: String {
            "{\(destination)/\(mask) \(gateway?.description ?? "*")}"
        }
    }

    public let address: String
    public let addressMask: String
    public let defaultGateway: String

    public init(address: String, addressMask: String, defaultGateway: String) {
        self.address = address
        self.addressMask = addressMask
        self.defaultGateway = defaultGateway
    }

    public var description: String {
        "addr \(address) netmask \(addressMask) gw \(defaultGateway)"
    }
}
