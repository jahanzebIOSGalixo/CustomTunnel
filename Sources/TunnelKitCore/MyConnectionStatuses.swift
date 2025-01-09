

import Foundation

public struct MyConnectionStatuses<T> {
    private let resetValue: T

    public var inbound: T

    public var outbound: T
    public var pair: (T, T) {
        return (inbound, outbound)
    }
    public init(val value: T) {
        inbound = value
        resetValue = value
        outbound = value
        
    }
    public mutating func reset() {
        outbound = resetValue
        inbound = resetValue
        
    }
}
