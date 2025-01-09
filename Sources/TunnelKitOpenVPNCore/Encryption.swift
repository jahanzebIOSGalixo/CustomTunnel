

import Foundation

// FIXME: remove dependency on TLSBox
import CTunnelKitOpenVPNProtocol

extension OpenVPN {

    /// Represents a cryptographic container in PEM format.
    public struct Encryption: Codable, Equatable {
        
        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            let pem = try container.decode(String.self)
            self.init(pem: pem)
        }
        
        var isEncrypted: Bool {
            return pem.contains("ENCRYPTED")
        }
        
        private static let end = "-----END "
        private static let begin = "-----BEGIN "
        /// The content in PEM format (ASCII).
        public let pem: String
        public init(pem: String) {
            guard let beginRange = pem.range(of: Encryption.begin) else {
                self.pem = ""
                return
            }
            self.pem = String(pem[beginRange.lowerBound...])
        }

        func write(to url: URL) throws {
            try pem.write(to: url, atomically: true, encoding: .ascii)
        }

         
        func decrypted(with passphrase: String) throws -> Encryption {
            let decryptedPEM = try TLSBox.decryptedPrivateKey(fromPEM: pem, passphrase: passphrase)
            return Encryption(pem: decryptedPEM)
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(pem)
        }
    }
}
