
import Foundation
import NetworkExtension

import TunnelKitCore

public class NETCP: NSObject, GalixoSocket {
    private static var linkContext = 0

    public let nwtpConnection: NWTCPConnection

    public init(impl: NWTCPConnection) {
        self.nwtpConnection = impl
        on = false
        off = false
    }

    public weak var delegate: GalixoSocketProtocol?
    private weak var queue: DispatchQueue?
    private var on: Bool
    public private(set) var off: Bool
    public var remoteAddress: String? {
        return (nwtpConnection.remoteAddress as? NWHostEndpoint)?.hostname
    }

    public var optimised: Bool {
        return nwtpConnection.hasBetterPath
    }

    

    public func listen(queue: DispatchQueue, activeTimeout: Int) {
        on = false

        self.queue = queue
        queue.arrange(after: .milliseconds(activeTimeout)) { [weak self] in
            guard let _self = self else {
                return
            }
            guard _self.on else {
                _self.delegate?.socketDidTimeout(_self)
                return
            }
        }
        nwtpConnection.addObserver(self, forKeyPath: #keyPath(NWTCPConnection.state), options: [.initial, .new], context: &NETCP.linkContext)
        nwtpConnection.addObserver(self, forKeyPath: #keyPath(NWTCPConnection.hasBetterPath), options: .new, context: &NETCP.linkContext)
    }

    public func stopListening() {
        nwtpConnection.removeObserver(self, forKeyPath: #keyPath(NWTCPConnection.state), context: &NETCP.linkContext)
        nwtpConnection.removeObserver(self, forKeyPath: #keyPath(NWTCPConnection.hasBetterPath), context: &NETCP.linkContext)
    }

    

    public func upgraded() -> GalixoSocket? {
        guard nwtpConnection.hasBetterPath else {
            return nil
        }
        return NETCP(impl: NWTCPConnection(upgradeFor: nwtpConnection))
    }

    public func shutdown() {
        nwtpConnection.writeClose()
        nwtpConnection.cancel()
    }
    // MARK: Connection KVO (any queue)

    public override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey: Any]?, context: UnsafeMutableRawPointer?) {
        guard context == &NETCP.linkContext else {
            super.observeValue(forKeyPath: keyPath, of: object, change: change, context: context)
            return
        }
//        if let keyPath = keyPath {
//            log.debug("KVO change reported (\(anyPointer(object)).\(keyPath))")
//        }
        queue?.async {
            self.observeConnectionChanges(forKeyPath: keyPath, on: object)
        }
    }
    
    private func handleConnectionStateChange(connection: NWTCPConnection) {
        if let _ = connection.remoteAddress {
            // Handle resolved endpoint if necessary
        }

        switch connection.state {
        case .connected:
            guard !on else { return }
            on = true
            delegate?.socketDidBecomeActive(self)

        case .cancelled:
            off = true
            delegate?.socket(self, didShutdownWithFailure: false)

        case .disconnected:
            off = true
            delegate?.socket(self, didShutdownWithFailure: true)

        default:
            break
        }
    }

    private func handleBetterPathDetection(connection: NWTCPConnection) {
        guard connection.hasBetterPath else { return }
        delegate?.socketHasBetterPath(self)
    }

    private func observeConnectionChanges(forKeyPath keyPath: String?, on object: Any?) {
        guard let connection = object as? NWTCPConnection, connection == self.nwtpConnection else { return }
        guard let keyPath = keyPath else { return }

        switch keyPath {
        case #keyPath(NWTCPConnection.state):
            handleConnectionStateChange(connection: connection)

        case #keyPath(NWTCPConnection.hasBetterPath):
            handleBetterPathDetection(connection: connection)

        default:
            break
        }
    }
}

extension NETCP {
    public override var description: String {
        guard let hostEndpoint = nwtpConnection.endpoint as? NWHostEndpoint else {
            return nwtpConnection.endpoint.maskedDescription
        }
        return "\(hostEndpoint.hostname.maskedDescription):\(hostEndpoint.port)"
    }
}
