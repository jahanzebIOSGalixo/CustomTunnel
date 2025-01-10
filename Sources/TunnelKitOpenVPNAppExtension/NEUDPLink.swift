////
////  NEUDPLink.swift
////  TunnelKit
////
////  Created by Davide De Rosa on 5/23/19.
////  Copyright (c) 2024 Davide De Rosa. All rights reserved.
////
////  https://github.com/passepartoutvpn
////
////  This file is part of TunnelKit.
////
////  TunnelKit is free software: you can redistribute it and/or modify
////  it under the terms of the GNU General Public License as published by
////  the Free Software Foundation, either version 3 of the License, or
////  (at your option) any later version.
////
////  TunnelKit is distributed in the hope that it will be useful,
////  but WITHOUT ANY WARRANTY; without even the implied warranty of
////  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
////  GNU General Public License for more details.
////
////  You should have received a copy of the GNU General Public License
////  along with TunnelKit.  If not, see <http://www.gnu.org/licenses/>.
////
//
//import Foundation
//import NetworkExtension
//import TunnelKitCore
//import TunnelKitAppExtension
//import TunnelKitOpenVPNCore
//import TunnelKitOpenVPNProtocol
//
//class NEUDPLink: URLDelegate {
//    private let impl: NWUDPSession
//
//    private let maxDatagrams: Int
//
//    private let xor: ConnectionMethod
//
//    init(impl: NWUDPSession, maxDatagrams: Int? = nil, xorMethod: OpenVPN.XORMethod?) {
//        self.impl = impl
//        self.maxDatagrams = maxDatagrams ?? 200
//        xor = ConnectionMethod(method: xorMethod)
//    }
//
//    // MARK: LinkInterface
//
//    let isReliable: Bool = false
//
//    var remoteAddress: String? {
//        (impl.resolvedEndpoint as? NWHostEndpoint)?.hostname
//    }
//
//    var remoteProtocol: String? {
//        guard let remote = impl.resolvedEndpoint as? NWHostEndpoint else {
//            return nil
//        }
//        return "UDP:\(remote.port)"
//    }
//
//    var packetBufferSize: Int {
//        return maxDatagrams
//    }
//
//    func readingCompletion(task: DispatchQueue, _ handler: @escaping ([Data]?, Error?) -> Void) {
//
//        // WARNING: runs in Network.framework queue
//        impl.setReadHandler({ [weak self] packets, error in
//            guard let self = self else {
//                return
//            }
//            var packetsToUse: [Data]?
//            if let packets = packets {
//                packetsToUse = self.xor.checkData(packets, isActive: false)
//            }
//            task.sync {
//                handler(packetsToUse, error)
//            }
//        }, maxDatagrams: maxDatagrams)
//    }
//
//    func singleDataWritten(_ packet: Data, completionHandler: ((Error?) -> Void)?) {
//        let dataToUse = xor.checkData(packet, isActive: true)
//        impl.writeDatagram(dataToUse) { error in
//            completionHandler?(error)
//        }
//    }
//
//    func multiplePacketsDataWritten(_ packets: [Data], completionHandler: ((Error?) -> Void)?) {
//        let packetsToUse = xor.checkData(packets, isActive: true)
//        impl.writeMultipleDatagrams(packetsToUse) { error in
//            completionHandler?(error)
//        }
//    }
//}
//
//extension NEUDP: URLGeneratorProtocol {
//    public func link(userObject: Any?) -> URLDelegate {
//        let xorMethod = userObject as? OpenVPN.XORMethod
//        return NEUDPLink(impl: nwSession, maxDatagrams: nil, xorMethod: xorMethod)
//    }
//}
