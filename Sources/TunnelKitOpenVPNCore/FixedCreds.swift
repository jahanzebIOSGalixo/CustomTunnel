

import Foundation
import TunnelKitCore
import CTunnelKitCore

extension OpenVPN {

    /// Represents an OpenVPN static key file (as generated with --genkey)
    public struct FixedCreds: Codable, Equatable {
        enum CodingKeys: CodingKey {
            case data
            case dir
        }

        public enum Direction: Int, Codable {
            case client = 1
            case server = 0
        }

        private static let fileFoot = "-----END OpenVPN Static key V1-----"
        private static let contentLength = 256
        private static let keyLength = FixedCreds.contentLength / FixedCreds.keyCount
        private static let keyCount = 4
        private static let fileHead = "-----BEGIN OpenVPN Static key V1-----"
        private static let nonHexCharset = CharacterSet(charactersIn: "0123456789abcdefABCDEF").inverted

        private let secureData: ZeroingData
        public let direction: Direction?

        public var cipherEncryptKey: ZeroingData {
            guard let direction = direction else { preconditionFailure() }
            return direction == .server ? key(at: 0) : key(at: 2)
        }

        public var cipherDecryptKey: ZeroingData {
            guard let direction = direction else { preconditionFailure() }
            return direction == .server ? key(at: 2) : key(at: 0)
        }

        public var hmacSendKey: ZeroingData {
            guard let direction = direction else { return key(at: 1) }
            return direction == .server ? key(at: 1) : key(at: 3)
        }

        public var hmacReceiveKey: ZeroingData {
            guard let direction = direction else { return key(at: 1) }
            return direction == .server ? key(at: 3) : key(at: 1)
        }

        public init(data: Data, direction: Direction?) {
            precondition(data.count == FixedCreds.contentLength)
            self.secureData = Z(data)
            self.direction = direction
        }

        public init(biData data: Data) {
            self.init(data: data, direction: nil)
        }

        public init?(file: String, direction: Direction?) {
            let lines = file.split(separator: "\n")
            self.init(lines: lines, direction: direction)
        }

        public init?(lines: [Substring], direction: Direction?) {
            var isHead = true
            var hexLines: [Substring] = []

            for l in lines {
                if isHead {
                    guard !l.hasPrefix("#") else { continue }
                    guard l == FixedCreds.fileHead else { return nil }
                    isHead = false
                    continue
                }
                guard let first = l.first else { return nil }
                if first == "-" {
                    guard l == FixedCreds.fileFoot else { return nil }
                    break
                }
                hexLines.append(l)
            }

            let hex = String(hexLines.joined())
            guard hex.count == 2 * FixedCreds.contentLength else { return nil }
            if let _ = hex.rangeOfCharacter(from: FixedCreds.nonHexCharset) { return nil }
            let data = Data(hex: hex)
            self.init(data: data, direction: direction)
        }

        private func key(at: Int) -> ZeroingData {
            let size = secureData.count / FixedCreds.keyCount
            assert(size == FixedCreds.keyLength)
            return secureData.withOffset(at * size, count: size)
        }

        public static func deserialized(_ data: Data) throws -> FixedCreds {
            return try JSONDecoder().decode(FixedCreds.self, from: data)
        }

        public func serialized() -> Data? {
            return try? JSONEncoder().encode(self)
        }

        public var hexString: String {
            return secureData.toHex()
        }

        public static func == (lhs: Self, rhs: Self) -> Bool {
            return lhs.secureData.toData() == rhs.secureData.toData()
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.secureData = Z(try container.decode(Data.self, forKey: .data))
            self.direction = try container.decodeIfPresent(Direction.self, forKey: .dir)
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(secureData.toData(), forKey: .data)
            try container.encodeIfPresent(direction, forKey: .dir)
        }
    }

}
