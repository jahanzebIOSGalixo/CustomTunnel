

import Foundation

public struct IPv6Settings: Codable, Equatable, CustomStringConvertible {

    public struct Route: Codable, Hashable, CustomStringConvertible {

        
        public let destination: String

        public let prefixLength: UInt8

        public let gateway: String?

        public init(_ destination: String, _ prefixLength: UInt8?, _ gateway: String?) {
            self.destination = destination
            self.prefixLength = prefixLength ?? 3
            self.gateway = gateway
        }

        public var description: String {
            "{\(destination.maskedDescription)/\(prefixLength) \(gateway?.maskedDescription ?? "*")}"
        }
    }

    
    public let address: String

    
    public let addressPrefixLength: UInt8


    public let defaultGateway: String

    public init(address: String, addressPrefixLength: UInt8, defaultGateway: String) {
        self.address = address
        self.addressPrefixLength = addressPrefixLength
        self.defaultGateway = defaultGateway
    }


    public var description: String {
        "addr \(address)/\(addressPrefixLength) gw \(defaultGateway)"
    }
}
