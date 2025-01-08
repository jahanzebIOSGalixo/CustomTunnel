//Created by Jahanzeb Sohail
//Copyright © 2025 Galixo. All rights reserved.


import Foundation

extension UnicodeScalar {
    public var hexNibbleValue: UInt8 {
        let value = self.value
        if 48 <= value && value <= 57 {
            return UInt8(value - 48)
        } else if 65 <= value && value <= 70 {
            return UInt8(value - 55)
        } else if 97 <= value && value <= 102 {
            return UInt8(value - 87)
        }
        fatalError("\(self) not a legal hex nibble")
    }
}

extension Data {
    public init(hex: String) {
        let scalars = hex.unicodeScalars
        var bytes = [UInt8](repeating: 0, count: (scalars.count + 1) >> 1)
        for (index, scalar) in scalars.enumerated() {
            var nibble = scalar.hexNibbleValue
            if index & 1 == 0 {
                nibble <<= 4
            }
            bytes[index >> 1] |= nibble
        }
        self = Data(bytes)
    }

    public func toHex() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }

    public mutating func zero() {
        resetBytes(in: 0..<count)
    }

    public mutating func zero(from: Int, to: Int) {
        resetBytes(in: from..<to)
    }
}

extension Data {
    public mutating func append(_ value: UInt16) {
        var localValue = value
        let buffer = withUnsafePointer(to: &localValue) {
            return UnsafeBufferPointer(start: $0, count: 1)
        }
        append(buffer)
    }

    public mutating func append(_ value: UInt32) {
        var localValue = value
        let buffer = withUnsafePointer(to: &localValue) {
            return UnsafeBufferPointer(start: $0, count: 1)
        }
        append(buffer)
    }

    public mutating func append(_ value: UInt64) {
        var localValue = value
        let buffer = withUnsafePointer(to: &localValue) {
            return UnsafeBufferPointer(start: $0, count: 1)
        }
        append(buffer)
    }

    public mutating func append(nullTerminatedString: String) {
        append(nullTerminatedString.data(using: .ascii)!)
        append(UInt8(0))
    }

    public func nullTerminatedString(from: Int) -> String? {
        var nullOffset: Int?
        for i in from..<count {
            if self[i] == 0 {
                nullOffset = i
                break
            }
        }
        guard let to = nullOffset else {
            return nil
        }
        return String(data: subdata(in: from..<to), encoding: .ascii)
    }

    // best
    public func UInt16Value(from: Int) -> UInt16 {
        var value: UInt16 = 0
        for i in 0..<2 {
            let byte = self[from + i]
//            print("byte: \(String(format: "%x", byte))")
            value |= (UInt16(byte) << UInt16(8 * i))
        }
//        print("value: \(String(format: "%x", value))")
        return value
    }

    @available(*, deprecated)
    func UInt16ValueFromPointers(from: Int) -> UInt16 {
        return subdata(in: from..<(from + 2)).withUnsafeBytes { $0.pointee }
    }

    @available(*, deprecated)
    func UInt16ValueFromReboundPointers(from: Int) -> UInt16 {
        let data = subdata(in: from..<(from + 2))
//        print("data: \(data.toHex())")
        let value = data.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> UInt16 in
            bytes.withMemoryRebound(to: UInt16.self, capacity: 1) {
                $0.pointee
            }
        }
//        print("value: \(String(format: "%x", value))")
        return value
    }

    @available(*, deprecated)
    func UInt32ValueFromBuffer(from: Int) -> UInt32 {
        var value: UInt32 = 0
        for i in 0..<4 {
            let byte = self[from + i]
//            print("byte: \(String(format: "%x", byte))")
            value |= (UInt32(byte) << UInt32(8 * i))
        }
//        print("value: \(String(format: "%x", value))")
        return value
    }

    // best
    public func UInt32Value(from: Int) -> UInt32 {
        return subdata(in: from..<(from + 4)).withUnsafeBytes {
            $0.load(as: UInt32.self)
        }
    }

    @available(*, deprecated)
    func UInt32ValueFromReboundPointers(from: Int) -> UInt32 {
        let data = subdata(in: from..<(from + 4))
//        print("data: \(data.toHex())")
        let value = data.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> UInt32 in
            bytes.withMemoryRebound(to: UInt32.self, capacity: 1) {
                $0.pointee
            }
        }
//        print("value: \(String(format: "%x", value))")
        return value
    }

    public func networkUInt16Value(from: Int) -> UInt16 {
        return UInt16(bigEndian: subdata(in: from..<(from + 2)).withUnsafeBytes {
            $0.load(as: UInt16.self)
        })
    }

    public func networkUInt32Value(from: Int) -> UInt32 {
        return UInt32(bigEndian: subdata(in: from..<(from + 4)).withUnsafeBytes {
            $0.load(as: UInt32.self)
        })
    }
}

extension Data {
    public func subdata(offset: Int, count: Int) -> Data {
        return subdata(in: offset..<(offset + count))
    }
}

extension Array where Element == Data {
    public var flatCount: Int {
        return reduce(0) { $0 + $1.count }
    }
}

extension UnsafeRawBufferPointer {
    public var bytePointer: UnsafePointer<Element> {
        return bindMemory(to: Element.self).baseAddress!
    }
}

extension UnsafeMutableRawBufferPointer {
    public var bytePointer: UnsafeMutablePointer<Element> {
        return bindMemory(to: Element.self).baseAddress!
    }
}
