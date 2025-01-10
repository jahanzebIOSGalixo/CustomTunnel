

import Foundation
import NetworkExtension

import TunnelKitCore
import TunnelKitAppExtension
import TunnelKitOpenVPNCore
import TunnelKitOpenVPNManager



class HandShakeAlgo {
    private var connections: [ConectionStats]

    private var selectedConnections: Int
    
    init(configuration: OpenVPN.Configuration) {
        guard let remotes = configuration.processedRemotes, !remotes.isEmpty else {
            fatalError("No remotes provided")
        }
        self.connections = remotes.map(ConectionStats.init)
        selectedConnections = 0
    }
    
    var myConnection: ConectionStats? {
        guard selectedConnections < connections.count else {
            return nil
        }
        return connections[selectedConnections]
    }
    
    func setConnection(
        settings provider: NEProvider,
        threshhold: Int,
        task: DispatchQueue,
        completionHandler: @escaping (Result<GalixoSocket, GalixoTunnelErrors>) -> Void) {
        guard let remote = myConnection else {
            completionHandler(.failure(.exhaustedEndpoints))
            return
        }
        if remote.active, let endpoint = remote.currentEndpoint {

            let socket = provider.noConnection(url: endpoint)
            completionHandler(.success(socket))
            return
        }



        remote.testFucn(thresh: threshhold, task: task) {
            guard let endpoint = remote.currentEndpoint else {

                completionHandler(.failure(.dnsFailure))
                return
            }

            let socket = provider.noConnection(url: endpoint)
            completionHandler(.success(socket))
        }
    }
    
    func isActive() -> Bool {
        guard let remote = myConnection else {
            return false
        }
        return !remote.active || remote.currentEndpoint != nil
    }

    @discardableResult
    func newExtend() -> Bool {
        guard let remote = myConnection else {
            return false
        }

        if remote.nextEndpoint() {
            return true
        }

        selectedConnections += 1
        guard let _ = myConnection else {

            return false
        }
        return true
    }

    
}

private extension NEProvider {
    func noConnection(url endpoint: ServerConnectionDestination) -> GalixoSocket {
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
