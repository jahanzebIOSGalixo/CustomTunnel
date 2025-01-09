
import Foundation
import CTunnelKitOpenVPNCore

extension OpenVPN {

    /// Defines the type of compression algorithm.
    public enum CompressionAlgorithm: Int, Codable, CustomStringConvertible {

        case disabled
        case other
        case LZO
        public var native: CompressionAlgorithmNative {
            guard let val = CompressionAlgorithmNative(rawValue: rawValue) else {
                fatalError("invlaid")
            }
            return val
        }

        public var description: String {
            switch self {
            case .LZO:
                return "lzo"
            case .disabled:
                return "disabled"
            case .other:
                return "other"
            }
        }
    }
}
