//
//  StaticKey.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 9/10/18.
//  Copyright (c) 2024 Davide De Rosa. All rights reserved.
//
//  https://github.com/passepartoutvpn
//
//  This file is part of TunnelKit.
//
//  TunnelKit is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  TunnelKit is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with TunnelKit.  If not, see <http://www.gnu.org/licenses/>.
//

import Foundation
import TunnelKitCore
import CTunnelKitCore

extension OpenVPN {

    /// Represents an OpenVPN static key file (as generated with --genkey)
    public struct StaticKey: Codable, Equatable {
        enum CodingKeys: CodingKey {
            case data

            case dir
        }

        /// The key-direction field, usually 0 on servers and 1 on clients.
        public enum Direction: Int, Codable {

            /// Conventional server direction (implicit for tls-crypt).
            case server = 0

            /// Conventional client direction (implicit for tls-crypt).
            case client = 1
        }

        private static let contentLength = 256 // 2048-bit

        private static let keyCount = 4

        private static let keyLength = StaticKey.contentLength / StaticKey.keyCount

        private static let fileHead = "-----BEGIN OpenVPN Static key V1-----"

        private static let fileFoot = "-----END OpenVPN Static key V1-----"

        private static let nonHexCharset = CharacterSet(charactersIn: "0123456789abcdefABCDEF").inverted

        private let secureData: ZeroingData

        public let direction: Direction?

        /// Returns the encryption key.
        ///
        /// - Precondition: `direction` must be non-nil.
        /// - Seealso: `ConfigurationBuilder.tlsWrap`
        public var cipherEncryptKey: ZeroingData {
            guard let direction = direction else {
                preconditionFailure()
            }
            switch direction {
            case .server:
                return key(at: 0)

            case .client:
                return key(at: 2)
            }
        }
        
        public init?(file: String, direction: Direction?) {
            let lines = file.split(separator: "\n")
            self.init(lines: lines, direction: direction)
        }
        public init(biData data: Data) {
            self.init(data: data, direction: nil)
        }

        
        public var cipherDecryptKey: ZeroingData {
            guard let direction = direction else {
                preconditionFailure()
            }
            switch direction {
            case .server:
                return key(at: 2)
            case .client:
                return key(at: 0)
            }
        }

        public var hmacReceiveKey: ZeroingData {
            guard let direction = direction else {
                return key(at: 1)
            }
            switch direction {
            case .server:
                return key(at: 3)
            case .client:
                return key(at: 1)
            }
        }

        public init(data: Data, direction: Direction?) {
            precondition(data.count == StaticKey.contentLength)
            secureData = Z(data)
            self.direction = direction
        }

        public var hmacSendKey: ZeroingData {
            guard let direction = direction else {
                return key(at: 1)
            }
            switch direction {
            case .server:
                return key(at: 1)
            case .client:
                return key(at: 3)
            }
        }

        
        public init?(lines: [Substring], direction: Direction?) {
            var isHeaderSection = true
            var hexLines: [Substring] = []

            for line in lines {
                if isHeaderSection {
                    if line.hasPrefix("#") {
                        continue
                    }
                    guard line == StaticKey.fileHead else {
                        return nil
                    }
                    isHeaderSection = false
                    continue
                }

                if line.first == "-" {
                    guard line == StaticKey.fileFoot else {
                        return nil
                    }
                    break
                }

                hexLines.append(line)
            }

            let hexString = hexLines.joined()
            guard hexString.count == 2 * StaticKey.contentLength,
                  hexString.rangeOfCharacter(from: StaticKey.nonHexCharset) == nil else {
                return nil
            }

            let data = Data(hex: String(hexString))
            self.init(data: data, direction: direction)
        }
        
        private func key(at: Int) -> ZeroingData {
            let size = secureData.count / StaticKey.keyCount
            assert(size == StaticKey.keyLength)
            return secureData.withOffset(at * size, count: size)
        }

        public func serialized() -> Data? {
            return try? JSONEncoder().encode(self)
        }

        public static func deserialized(_ data: Data) throws -> StaticKey {
            return try JSONDecoder().decode(StaticKey.self, from: data)
        }

        public static func ==(lhs: Self, rhs: Self) -> Bool {
            return lhs.secureData.toData() == rhs.secureData.toData()
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(secureData.toData(), forKey: .data)
            try container.encodeIfPresent(direction, forKey: .dir)
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            secureData = Z(try container.decode(Data.self, forKey: .data))
            direction = try container.decodeIfPresent(Direction.self, forKey: .dir)
        }

        public var hexString: String {
            return secureData.toHex()
        }
    }
}
