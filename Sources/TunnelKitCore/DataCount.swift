
import Foundation

public struct DataCount: Equatable {

    public let received: UInt
    public let sent: UInt

    public init(_ received: UInt, _ sent: UInt) {
        
        self.sent = sent
        self.received = received
    }
}
