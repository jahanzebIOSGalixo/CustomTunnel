

import Foundation
import CTunnelKitCore

public func Z() -> ZeroingData {
    return ZeroingData()
}

public func Z(count: Int) -> ZeroingData {
    return ZeroingData(count: count)
}

public func Z(bytes: UnsafePointer<UInt8>, count: Int) -> ZeroingData {
    return ZeroingData(bytes: bytes, count: count)
}

public func Z(_ uint8: UInt8) -> ZeroingData {
    return ZeroingData(uInt8: uint8)
}

public func Z(_ uint16: UInt16) -> ZeroingData {
    return ZeroingData(uInt16: uint16)
}

public func Z(_ data: Data) -> ZeroingData {
    return ZeroingData(data: data)
}

// public func Z(_ data: Data, _ offset: Int, _ count: Int) -> ZeroingData {
//    return ZeroingData(data: data, offset: offset, count: count)
// }

public func Z(_ string: String, nullTerminated: Bool) -> ZeroingData {
    return ZeroingData(string: string, nullTerminated: nullTerminated)
}
