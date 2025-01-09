

import Foundation
import TunnelKitCore

class ResolvedRemote: CustomStringConvertible {
    let originalEndpoint: ServerConnectionDestination

    private(set) var isResolved: Bool

    private(set) var resolvedEndpoints: [ServerConnectionDestination]

    private var currentEndpointIndex: Int

    var currentEndpoint: ServerConnectionDestination? {
        guard currentEndpointIndex < resolvedEndpoints.count else {
            return nil
        }
        return resolvedEndpoints[currentEndpointIndex]
    }

    init(_ originalEndpoint: ServerConnectionDestination) {
        self.originalEndpoint = originalEndpoint
        isResolved = false
        resolvedEndpoints = []
        currentEndpointIndex = 0
    }
    
    func resolve(timeout: Int, queue: DispatchQueue, completionHandler: @escaping () -> Void) {
        SolverSND.dnsFromHost(originalEndpoint.address, timeout: timeout, queue: queue) { [weak self] in
            self?.handleResult($0)
            completionHandler()
        }
    }

    func nextEndpoint() -> Bool {
        currentEndpointIndex += 1
        return currentEndpointIndex < resolvedEndpoints.count
    }

    
    
    private func unknownHandling(nets: [ResolveDnsRec]) -> [ServerConnectionDestination] {
        let endpoints = nets.filter {
            $0.liked(for: originalEndpoint.proto)
        }.map {
            ServerConnectionDestination($0.address, originalEndpoint.proto)
        }

        return endpoints
    }

    private func handleResult(_ result: Result<[ResolveDnsRec], Error>) {
        switch result {
        case .success(let records):

            isResolved = true
            resolvedEndpoints = unknownHandling(nets: records)

        case .failure:

            isResolved = false
            resolvedEndpoints = []
        }
    }

    var description: String {
        "{\(originalEndpoint.maskedDescription), calculated: \(resolvedEndpoints.maskedDescription)}"
    }
}

private extension ResolveDnsRec {
    func liked(for proto: GalixoDestinationDelegate) -> Bool {
        if isIPv6 {
            return proto.socketType != .udp4 && proto.socketType != .tcp4
        } else {
            return proto.socketType != .udp6 && proto.socketType != .tcp6
        }
    }
}
