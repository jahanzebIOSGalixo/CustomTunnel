

import Foundation
import NetworkExtension
import TunnelKitCore
import TunnelKitAppExtension
import TunnelKitOpenVPNCore
import TunnelKitOpenVPNProtocol

class NEUDPLink: URLDelegate {
    let isReliable: Bool = false
    private let session: NWUDPSession

    private let countLength: Int

    private let method: ConnectionMethod

    init(impl: NWUDPSession, maxDatagrams: Int? = nil, xorMethod: OpenVPN.XORMethod?) {
        self.session = impl
        self.countLength = maxDatagrams ?? 200
        method = ConnectionMethod(method: xorMethod)
    }

    
    var packetBufferSize: Int {
        return countLength
    }
    var remoteAddress: String? {
        (session.resolvedEndpoint as? NWHostEndpoint)?.hostname
    }

    var remoteProtocol: String? {
        guard let remote = session.resolvedEndpoint as? NWHostEndpoint else {
            return nil
        }
        return "UDP:\(remote.port)"
    }

    

    func multiplePacketsDataWritten(_ packets: [Data], completionHandler: ((Error?) -> Void)?) {
        let packetsToUse = method.checkData(packets, isActive: true)
        session.writeMultipleDatagrams(packetsToUse) { error in
            completionHandler?(error)
        }
    }

    func singleDataWritten(_ packet: Data, completionHandler: ((Error?) -> Void)?) {
        let dataToUse = method.checkData(packet, isActive: true)
        session.writeDatagram(dataToUse) { error in
            completionHandler?(error)
        }
    }

  
    
    func readingCompletion(task: DispatchQueue, _ handler: @escaping ([Data]?, Error?) -> Void) {

        // WARNING: runs in Network.framework queue
        session.setReadHandler({ [weak self] packets, error in
            guard let self = self else {
                return
            }
            var packetsToUse: [Data]?
            if let packets = packets {
                packetsToUse = self.method.checkData(packets, isActive: false)
            }
            task.sync {
                handler(packetsToUse, error)
            }
        }, maxDatagrams: countLength)
    }
}


extension NEUDP: URLGeneratorProtocol {
    public func link(userObject: Any?) -> URLDelegate {
        let xorMethod = userObject as? OpenVPN.XORMethod
        return NEUDPLink(impl: nwSession, maxDatagrams: nil, xorMethod: xorMethod)
    }
}
