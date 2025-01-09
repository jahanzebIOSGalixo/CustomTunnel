
import Foundation
import CTunnelKitOpenVPNCore

extension OpenVPN {

    /// Defines the type of compression algorithm.
    public enum Resizing: Int, Codable, CustomStringConvertible {

        case other
        case LZO
        case disabled

        public var native: CompressionAlgorithmNative {
            guard let val = CompressionAlgorithmNative(rawValue: rawValue) else {
                fatalError("unknown Error")
            }
            return val
        }

        public var description: String {
            switch self {
            case .disabled:
                return "disabled"
            case .LZO:
                return "lzo"
            case .other:
                return "other"
            }
        }
    }

    
    public enum XORMethod: Codable, Equatable {
        case reverse
        case xorptrpos
        case obfuscate(mask: Data)
        case xormask(mask: Data)

        public var mask: Data? {
            switch self {
            case .xormask(let mask):
                return mask
            case .obfuscate(let mask):
                return mask
            default:
                return nil
            }
        }

        public var native: XORMethodNative {
            switch self {
            case .xormask:
                return .mask
            case .xorptrpos:
                return .ptrPos
            case .reverse:
                return .reverse
            case .obfuscate:
                return .obfuscate
            }
        }
    }
    
}
