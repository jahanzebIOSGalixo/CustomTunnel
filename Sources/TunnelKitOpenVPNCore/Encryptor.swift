

import Foundation

// FIXME: remove dependency on TLSBox
import CTunnelKitOpenVPNProtocol

extension OpenVPN {

    public struct Encryptor: Codable, Equatable {
        private static let begin = "-----BEGIN "
        private static let end = "-----END "

        public let pem: String

        var isEncrypted: Bool {
            return pem.contains("ENCRYPTED")
        }

        public init(pem: String) {
            guard let beginRange = pem.range(of: Encryptor.begin) else {
                self.pem = ""
                return
            }
            self.pem = String(pem[beginRange.lowerBound...])
        }

        func write(to url: URL) throws {
            try pem.write(to: url, atomically: true, encoding: .ascii)
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            let pem = try container.decode(String.self)
            self.init(pem: pem)
        }

        func decrypted(with passphrase: String) throws -> Encryptor {
            let decryptedPEM = try TLSBox.decryptedPrivateKey(fromPEM: pem, passphrase: passphrase)
            return Encryptor(pem: decryptedPEM)
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(pem)
        }
    }

}
