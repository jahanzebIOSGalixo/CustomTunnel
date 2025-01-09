

import Foundation

/// Represents a specific I/O interface meant to work at the link layer (e.g. TCP/IP).
public protocol URLDelegate: IOProtocol {
    var remoteAddress: String? { get }
    var isReliable: Bool { get }
    var packetBufferSize: Int { get }
    var remoteProtocol: String? { get }
    
}
