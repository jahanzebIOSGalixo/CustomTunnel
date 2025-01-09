import TunnelKitCore
import Foundation
import NetworkExtension


public class NETCPIMP: TunnelProtocol {
    private weak var nePacketTunnelFlow: NEPacketTunnelFlow?

    public init(nEPacketTunnelFlow: NEPacketTunnelFlow) {
        self.nePacketTunnelFlow = nEPacketTunnelFlow
    }

    // MARK: TunnelInterface

    public var constant: Bool {
        return false
    }

    // MARK: IOInterface

    public func readingCompletion(task: DispatchQueue, _ handler: @escaping ([Data]?, Error?) -> Void) {
        readingData(task, handler)
    }


    public func singleDataWritten(_ packet: Data, completionHandler: ((Error?) -> Void)?) {
        let protocolNumber = IPHeader.protocolNumber(inPacket: packet)
        nePacketTunnelFlow?.writePackets([packet], withProtocols: [protocolNumber])
        completionHandler?(nil)
    }
    
    private func readingData(_ task: DispatchQueue, _ handler: @escaping ([Data]?, Error?) -> Void) {

        // WARNING: runs in NEPacketTunnelFlow queue
        nePacketTunnelFlow?.readPackets { [weak self] (packets, _) in
            task.sync {
                self?.readingData(task, handler)
                handler(packets, nil)
            }
        }
    }

    public func multiplePacketsDataWritten(_ packets: [Data], completionHandler: ((Error?) -> Void)?) {
        let protocols = packets.map {
            IPHeader.protocolNumber(inPacket: $0)
        }
        nePacketTunnelFlow?.writePackets(packets, withProtocols: protocols)
        completionHandler?(nil)
    }
}
