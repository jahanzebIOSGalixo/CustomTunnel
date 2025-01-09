//
//  ConnectionStrategy.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 6/18/18.
//  Copyright (c) 2024 Davide De Rosa. All rights reserved.
//
//  https://github.com/passepartoutvpn
//
//  This file is part of TunnelKit.
//
//  TunnelKit is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  TunnelKit is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with TunnelKit.  If not, see <http://www.gnu.org/licenses/>.
//
//  This file incorporates work covered by the following copyright and
//  permission notice:
//
//      Copyright (c) 2018-Present Private Internet Access
//
//      Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
//      The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
//      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

import Foundation
import NetworkExtension

import TunnelKitCore
import TunnelKitAppExtension
import TunnelKitOpenVPNCore
import TunnelKitOpenVPNManager



class ConnectionStrategy {
    private var remotes: [ResolvedRemote]

    private var currentRemoteIndex: Int

    var currentRemote: ResolvedRemote? {
        guard currentRemoteIndex < remotes.count else {
            return nil
        }
        return remotes[currentRemoteIndex]
    }

    init(configuration: OpenVPN.Configuration) {
        guard let remotes = configuration.processedRemotes, !remotes.isEmpty else {
            fatalError("No remotes provided")
        }
        self.remotes = remotes.map(ResolvedRemote.init)
        currentRemoteIndex = 0
    }

    func hasEndpoints() -> Bool {
        guard let remote = currentRemote else {
            return false
        }
        return !remote.isResolved || remote.currentEndpoint != nil
    }

    @discardableResult
    func tryNextEndpoint() -> Bool {
        guard let remote = currentRemote else {
            return false
        }

        if remote.nextEndpoint() {
            return true
        }

        currentRemoteIndex += 1
        guard let _ = currentRemote else {

            return false
        }
        return true
    }

    func createSocket(
        from provider: NEProvider,
        timeout: Int,
        queue: DispatchQueue,
        completionHandler: @escaping (Result<GalixoSocket, TunnelKitOpenVPNError>) -> Void) {
        guard let remote = currentRemote else {
            completionHandler(.failure(.exhaustedEndpoints))
            return
        }
        if remote.isResolved, let endpoint = remote.currentEndpoint {

            let socket = provider.createSocket(to: endpoint)
            completionHandler(.success(socket))
            return
        }



        remote.resolve(timeout: timeout, queue: queue) {
            guard let endpoint = remote.currentEndpoint else {

                completionHandler(.failure(.dnsFailure))
                return
            }

            let socket = provider.createSocket(to: endpoint)
            completionHandler(.success(socket))
        }
    }
}

private extension NEProvider {
    func createSocket(to endpoint: ServerConnectionDestination) -> GalixoSocket {
        let ep = NWHostEndpoint(hostname: endpoint.address, port: "\(endpoint.proto.port)")
        switch endpoint.proto.socketType {
        case .udp, .udp4, .udp6:
            let impl = createUDPSession(to: ep, from: nil)
            return NEUDP(impl: impl)

        case .tcp, .tcp4, .tcp6:
            let impl = createTCPConnection(to: ep, enableTLS: false, tlsParameters: nil, delegate: nil)
            return NETCP(impl: impl)
        }
    }
}
