
import Foundation
import TunnelKitCore


class ConectionStats: CustomStringConvertible {
    let stats: ServerConnectionDestination

    private(set) var active: Bool

    private(set) var port: [ServerConnectionDestination]

    private var selected: Int

    

    init(_ originalEndpoint: ServerConnectionDestination) {
        self.stats = originalEndpoint
        active = false
        port = []
        selected = 0
    }

    var currentEndpoint: ServerConnectionDestination? {
        guard selected < port.count else {
            return nil
        }
        return port[selected]
    }
    
    func nextEndpoint() -> Bool {
        selected += 1
        return selected < port.count
    }

    func testFucn(thresh: Int, task: DispatchQueue, completionHandler: @escaping () -> Void) {
        SolverSND.dnsFromHost(stats.address, timeout: thresh, queue: task) { [weak self] in
            self?.handleResult($0)
            completionHandler()
        }
    }

    private func handleResult(_ result: Result<[ResolveDnsRec], Error>) {
        switch result {
        case .success(let records):

            active = true
            port = unrolledEndpoints(records: records)

        case .failure:

            active = false
            port = []
        }
    }

    private func unrolledEndpoints(records: [ResolveDnsRec]) -> [ServerConnectionDestination] {
        let endpoints = records.filter {
            $0.isCompatible(withProtocol: stats.proto)
        }.map {
            ServerConnectionDestination($0.address, stats.proto)
        }

        return endpoints
    }

    // MARK: CustomStringConvertible

    var description: String {
        "{\(stats.maskedDescription), resolved: \(port.maskedDescription)}"
    }
}

private extension ResolveDnsRec {
    func isCompatible(withProtocol proto: GalixoDestinationDelegate) -> Bool {
        if isIPv6 {
            return proto.socketType != .udp4 && proto.socketType != .tcp4
        } else {
            return proto.socketType != .udp6 && proto.socketType != .tcp6
        }
    }
}
