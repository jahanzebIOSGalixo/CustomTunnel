

import Foundation
import NetworkExtension

import TunnelKitCore
import TunnelKitAppExtension
import TunnelKitOpenVPNCore
import TunnelKitOpenVPNManager



class AlgoConnection {
    private var number: Int
    private var addresses: [ResolvedRemote]
    
    var selectedAddress: ResolvedRemote? {
        guard number < addresses.count else {
            return nil
        }
        return addresses[number]
    }

    init(configuration: OpenVPN.Configuration) {
        guard let remotes = configuration.processedRemotes, !remotes.isEmpty else {
            fatalError("No remotes provided")
        }
        self.addresses = remotes.map(ResolvedRemote.init)
        number = 0
    }

    @discardableResult
    func tryNextEndpoint() -> Bool {
        guard let remote = selectedAddress else {
            return false
        }

        if remote.nextEndpoint() {
            return true
        }

        number += 1
        guard let _ = selectedAddress else {

            return false
        }
        return true
    }

    func startNetworking(
        from network: NEProvider,
        limit: Int,
        task: DispatchQueue,
        completionHandler: @escaping (Result<GalixoSocket, TunnelKitOpenVPNError>) -> Void) {
        guard let address = selectedAddress else {
            completionHandler(.failure(.exhaustedEndpoints))
            return
        }
        if address.isResolved, let endpoint = address.currentEndpoint {

            let socket = network.configureNetwork(to: endpoint)
            completionHandler(.success(socket))
            return
        }

        address.resolve(timeout: limit, queue: task) {
            guard let endpoint = address.currentEndpoint else {
                completionHandler(.failure(.dnsFailure))
                return
            }

            let socket = network.configureNetwork(to: endpoint)
            completionHandler(.success(socket))
        }
    }
}

private extension NEProvider {
    
    func configureNetwork(to endpoint: ServerConnectionDestination) -> GalixoSocket {
        // Create NWHostEndpoint based on the given address and port
        let nwEndpoint = NWHostEndpoint(hostname: endpoint.address, port: "\(endpoint.proto.port)")
        
        // Switch on the protocol type to determine the socket to create
        switch endpoint.proto.socketType {
        case .udp, .udp4, .udp6:
            let udpSession = createUDPSession(to: nwEndpoint, from: nil)
            return NEUDP(impl: udpSession)

        case .tcp, .tcp4, .tcp6:
            let tcpConnection = createTCPConnection(
                to: nwEndpoint,
                enableTLS: false,
                tlsParameters: nil,
                delegate: nil
            )
            return NETCP(impl: tcpConnection)
        }
    }

}
