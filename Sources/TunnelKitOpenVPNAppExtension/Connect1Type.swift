

import Foundation
import NetworkExtension
import TunnelKitCore
import TunnelKitAppExtension
import TunnelKitOpenVPNCore
import CTunnelKitOpenVPNProtocol

class Connect1Type: URLDelegate {
    private let data: Data?
    private let totalLength: Int
    private let knct: NWTCPConnection
    private let encryption: OpenVPN.XORMethod?
    let isReliable: Bool = true
    

    init(impl: NWTCPConnection, maxPacketSize: Int? = nil, xorMethod: OpenVPN.XORMethod?) {
        self.knct = impl
        self.totalLength = maxPacketSize ?? (512 * 1024)
        self.encryption = xorMethod
        data = xorMethod?.mask
    }
    
    var remoteProtocol: String? {
        guard let remote = knct.remoteAddress as? NWHostEndpoint else {
            return nil
        }
        return "TCP:\(remote.port)"
    }
    var remoteAddress: String? {
        (knct.remoteAddress as? NWHostEndpoint)?.hostname
    }

    

    var packetBufferSize: Int {
        return totalLength
    }

    func readingCompletion(task: DispatchQueue, _ handler: @escaping ([Data]?, Error?) -> Void) {
        bufferGet(task, Data(), handler)
    }

    private func bufferGet(_ queue: DispatchQueue, _ buffer: Data, _ handler: @escaping ([Data]?, Error?) -> Void) {

        // WARNING: runs in Network.framework queue
        knct.readMinimumLength(2, maximumLength: packetBufferSize) { [weak self] (data, error) in
            guard let self = self else {
                return
            }
            queue.sync {
                guard (error == nil), let data = data else {
                    handler(nil, error)
                    return
                }

                var next = buffer
                next.append(contentsOf: data)
                var threshold = 0
                let packets = PacketStream.packets(
                    fromInboundStream: next,
                    until: &threshold,
                    xorMethod: self.encryption?.native ?? .none,
                    xorMask: self.data
                )
                next = next.subdata(in: threshold..<next.count)
                self.bufferGet(queue, next, handler)

                handler(packets, nil)
            }
        }
    }

    func multiplePacketsDataWritten(_ packets: [Data], completionHandler: ((Error?) -> Void)?) {
        let stream = PacketStream.outboundStream(
            fromPackets: packets,
            xorMethod: encryption?.native ?? .none,
            xorMask: data
        )
        knct.write(stream) { (error) in
            completionHandler?(error)
        }
    }
    
    func singleDataWritten(_ packet: Data, completionHandler: ((Error?) -> Void)?) {
        let stream = PacketStream.outboundStream(
            fromPacket: packet,
            xorMethod: encryption?.native ?? .none,
            xorMask: data
        )
        knct.write(stream) { (error) in
            completionHandler?(error)
        }
    }

    
}

extension NETCP: URLGeneratorProtocol {
    public func link(userObject: Any?) -> URLDelegate {
        let xorMethod = userObject as? OpenVPN.XORMethod
        return Connect1Type(impl: nwtpConnection, maxPacketSize: nil, xorMethod: xorMethod)
    }
}
