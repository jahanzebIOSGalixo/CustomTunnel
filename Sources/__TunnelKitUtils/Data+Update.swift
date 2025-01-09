//Created by Jahanzeb Sohail

import Foundation
extension Data {

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

    public func UInt16Value(from: Int) -> UInt16 {
        var value: UInt16 = 0
        for i in 0..<2 {
            let byte = self[from + i]
            value |= (UInt16(byte) << UInt16(8 * i))
        }

        return value
    }

    public func UInt32Value(from: Int) -> UInt32 {
        return subdata(in: from..<(from + 4)).withUnsafeBytes {
            $0.load(as: UInt32.self)
        }
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
    public init(hex: String) {
        let characters = hex.unicodeScalars
        var byteArray = [UInt8](repeating: 0, count: (characters.count + 1) / 2)
        
        for i in 0..<characters.count {
            let currentScalar = characters[characters.index(characters.startIndex, offsetBy: i)]
            let currentNibble = currentScalar.galixoHexNibbleValue
            
            let position = i / 2
            if i % 2 == 0 {
                byteArray[position] |= currentNibble << 4
            } else {
                byteArray[position] |= currentNibble
            }
        }
        
        self = Data(byteArray)
    }



    public func toHex() -> String {
        let format = "%02hhx"
        return map { String(format: format, $0) }.joined()
    }
}

extension Data {
    public func galixoSubdata(offset: Int, count: Int) -> Data {
        return subdata(in: offset..<(offset + count))
    }
}

extension UnsafeRawBufferPointer {
    public var galixoPointer: UnsafePointer<Element> {
        return bindMemory(to: Element.self).baseAddress!
    }
}

extension UnsafeMutableRawBufferPointer {
    public var galixoPointer: UnsafeMutablePointer<Element> {
        return bindMemory(to: Element.self).baseAddress!
    }
}

extension UnicodeScalar {
    public var galixoHexNibbleValue: UInt8 {
        let value = self.value
        switch value {
        case 48...57: // Numbers 0-9
            return UInt8(value - 48)
        case 65...70: // Uppercase letters A-F
            return UInt8(value - 55)
        case 97...102: // Lowercase letters a-f
            return UInt8(value - 87)
        default:
            fatalError("\(self) is not a valid hex nibble value. Please try again.")
        }
    }

}

extension Array where Element == Data {
    public var flatCount: Int {
        return reduce(0) { $0 + $1.count }
    }
}
