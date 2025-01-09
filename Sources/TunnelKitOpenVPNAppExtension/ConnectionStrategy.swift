

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
