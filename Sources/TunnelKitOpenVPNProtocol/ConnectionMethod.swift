

import Foundation
import TunnelKitOpenVPNCore

public struct ConnectionMethod {
    private let encryptionType: OpenVPN.XORMethod?

    public init(method: OpenVPN.XORMethod?) {
        self.encryptionType = method
    }
    
    public func checkData(_ packet: Data, isActive: Bool) -> Data {
        guard let encryptionType = encryptionType else {
            return packet
        }
        switch encryptionType {
        case .xormask(let mask):
            return Self.xormask(packet: packet, mask: mask)

        case .xorptrpos:
            return Self.xorptrpos(packet: packet)

        case .reverse:
            return Self.reverse(packet: packet)

        case .obfuscate(let mask):
            if isActive {
                return Self.xormask(packet: Self.xorptrpos(packet: Self.reverse(packet: Self.xorptrpos(packet: packet))), mask: mask)
            } else {
                return Self.xorptrpos(packet: Self.reverse(packet: Self.xorptrpos(packet: Self.xormask(packet: packet, mask: mask))))
            }
        }
    }

    public func checkData(_ packets: [Data], isActive: Bool) -> [Data] {
        guard let _ = encryptionType else {
            return packets
        }
        return packets.map {
            checkData($0, isActive: isActive)
        }
    }
}

extension ConnectionMethod {
    private static func reverse(packet: Data) -> Data {
        Data(([UInt8](packet))[0..<1] + ([UInt8](packet)[1...]).reversed())
    }
    
    private static func xormask(packet: Data, mask: Data) -> Data {
        Data(packet.enumerated().map { (index, byte) in
            byte ^ [UInt8](mask)[index % mask.count]
        })
    }

    private static func xorptrpos(packet: Data) -> Data {
        Data(packet.enumerated().map { (index, byte) in
            byte ^ UInt8(truncatingIfNeeded: index &+ 1)
        })
    }

    
}
