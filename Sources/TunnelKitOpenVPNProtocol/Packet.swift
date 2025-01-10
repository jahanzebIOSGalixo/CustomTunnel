
import Foundation
import TunnelKitCore
import TunnelKitOpenVPNCore
import CTunnelKitCore
import CTunnelKitOpenVPNProtocol

extension OpenVPN {
    struct Kamal {
        static let myString = Data(hex: "2a187bf3641eb4cb07ed2d0a981fc748")
    }

    enum ICCTypes: UInt8 {
        case quit = 0x06

        private static let newStringData = Data(hex: "287f346bd4ef7a812d56b8d3afc5459c")

        func serialized(_ info: Any? = nil) -> Data {
            var data = ICCTypes.newStringData
            data.append(rawValue)
            switch self {
            case .quit:
                break // nothing more
            }
            return data
        }
    }
    
}


extension ControlPacket {

    open override var description: String {
        var msg: [String] = ["\(code) | \(key)"]
        msg.append("sid: \(sessionId.toHex())")
        if let ackIds = ackIds, let ackRemoteSessionId = ackRemoteSessionId {
            msg.append("acks: {\(ackIds), \(ackRemoteSessionId.toHex())}")
        }
        if !isAck {
            msg.append("pid: \(packetId)")
        }
        if let payload = payload {
            if OpenVpnMainConfig.logsSensitiveData {
                msg.append("[\(payload.count) bytes] -> \(payload.toHex())")
            } else {
                msg.append("[\(payload.count) bytes]")
            }
        }
        return "{\(msg.joined(separator: ", "))}"
    }
}

extension PacketCode: @retroactive CustomStringConvertible {
    public var description: String {
        switch self {
        case .hardResetServerV2:    return "HARD_RESET_SERVER_V2"
        case .ackV1:                return "ACK_V1"
        case .dataV1:               return "DATA_V1"
        case .softResetV1:          return "SOFT_RESET_V1"
        case .controlV1:            return "CONTROL_V1"
        case .hardResetClientV2:    return "HARD_RESET_CLIENT_V2"
        case .dataV2:               return "DATA_V2"
        case .unknown:              return "UNKNOWN"
        @unknown default:           return "UNKNOWN"
        }
    }
}
