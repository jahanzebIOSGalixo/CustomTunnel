
import Foundation
import NetworkExtension
import TunnelKitCore

public class NEUDP: NSObject, GenericSocket {
    private static var linkContext = 0

    public let nwSession: NWUDPSession

    public init(impl: NWUDPSession) {
        self.nwSession = impl

        on = false
        off = false
    }

    private weak var queue: DispatchQueue?

    private var on: Bool

    public private(set) var off: Bool

    public var remoteAddress: String? {
        return (nwSession.resolvedEndpoint as? NWHostEndpoint)?.hostname
    }

    public var optimised: Bool {
        return nwSession.hasBetterPath
    }

    public weak var delegate: GenericSocketDelegate?

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
        nwSession.addObserver(self, forKeyPath: #keyPath(NWUDPSession.state), options: [.initial, .new], context: &NEUDP.linkContext)
        nwSession.addObserver(self, forKeyPath: #keyPath(NWUDPSession.hasBetterPath), options: .new, context: &NEUDP.linkContext)
    }

    public func stopListening() {
        nwSession.removeObserver(self, forKeyPath: #keyPath(NWUDPSession.state), context: &NEUDP.linkContext)
        nwSession.removeObserver(self, forKeyPath: #keyPath(NWUDPSession.hasBetterPath), context: &NEUDP.linkContext)
    }

    public func shutdown() {
        nwSession.cancel()
    }

    public func upgraded() -> GenericSocket? {
        guard nwSession.hasBetterPath else {
            return nil
        }
        return NEUDP(impl: NWUDPSession(upgradeFor: nwSession))
    }

    // MARK: Connection KVO (any queue)

    public override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey: Any]?, context: UnsafeMutableRawPointer?) {
        guard context == &NEUDP.linkContext else {
            super.observeValue(forKeyPath: keyPath, of: object, change: change, context: context)
            return
        }

        queue?.async {
            self.observeValueInTunnelQueue(forKeyPath: keyPath, of: object, change: change, context: context)
        }
    }

    private func observeValueInTunnelQueue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey: Any]?, context: UnsafeMutableRawPointer?) {

        guard let impl = object as? NWUDPSession, (impl == self.nwSession) else {

            return
        }
        guard let keyPath = keyPath else {
            return
        }
        switch keyPath {
        case #keyPath(NWUDPSession.state):
            if let resolvedEndpoint = impl.resolvedEndpoint {

            } else {

            }

            switch impl.state {
            case .ready:
                guard !on else {
                    return
                }
                on = true
                delegate?.socketDidBecomeActive(self)

            case .cancelled:
                off = true
                delegate?.socket(self, didShutdownWithFailure: false)

            case .failed:
                off = true
                delegate?.socket(self, didShutdownWithFailure: true)

            default:
                break
            }

        case #keyPath(NWUDPSession.hasBetterPath):
            guard impl.hasBetterPath else {
                break
            }

            delegate?.socketHasBetterPath(self)

        default:
            break
        }
    }
}

extension NEUDP {
    public override var description: String {
        guard let hostEndpoint = nwSession.endpoint as? NWHostEndpoint else {
            return nwSession.endpoint.maskedDescription
        }
        return "\(hostEndpoint.hostname.maskedDescription):\(hostEndpoint.port)"
    }
}
