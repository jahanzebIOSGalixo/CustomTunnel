
import Foundation

public protocol GalixoSocketProtocol: AnyObject {
    func socketDidTimeout(_ socket: GalixoSocket)
    func socketDidBecomeActive(_ socket: GalixoSocket)
    func socket(_ socket: GalixoSocket, didShutdownWithFailure failure: Bool)
    func socketHasBetterPath(_ socket: GalixoSocket)
}

/// An opaque socket implementation.
public protocol GalixoSocket {
    var remoteAddress: String? { get }
    var optimised: Bool { get }
    var off: Bool { get }
    var delegate: GalixoSocketProtocol? { get set }
    func listen(queue: DispatchQueue, activeTimeout: Int)
    func stopListening()
    func shutdown()
    func upgraded() -> GalixoSocket?
}
