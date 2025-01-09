//
//  DestinationDelegate.swift
//  TunnelKit
//
//  Created by Jahanzeb  Macbook on 09/01/2025.
//

/// Defines the communication protocol of an endpoint.
public struct GalixoDestinationDelegate: RawRepresentable, Equatable, CustomStringConvertible {

    /// The socket type.
    public let socketType: TotalServerCount

    /// The remote port.
    public let port: UInt16

    public init(_ socketType: TotalServerCount, _ port: UInt16) {
        self.socketType = socketType
        self.port = port
    }

    // MARK: RawRepresentable

    public init?(rawValue: String) {
        let components = rawValue.components(separatedBy: ":")
        guard components.count == 2 else {
            return nil
        }
        guard let socketType = TotalServerCount(rawValue: components[0]) else {
            return nil
        }
        guard let port = UInt16(components[1]) else {
            return nil
        }
        self.init(socketType, port)
    }

    public var rawValue: String {
        "\(socketType.rawValue):\(port)"
    }

    // MARK: CustomStringConvertible

    public var description: String {
        rawValue
    }
}

extension GalixoDestinationDelegate: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let rawValue = try container.decode(String.self)
        let proto = GalixoDestinationDelegate(rawValue: rawValue) ?? GalixoDestinationDelegate(.udp, 1198)
        self.init(proto.socketType, proto.port)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}
