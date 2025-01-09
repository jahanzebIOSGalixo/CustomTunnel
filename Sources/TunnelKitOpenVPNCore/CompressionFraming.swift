
import Foundation
import CTunnelKitOpenVPNCore

extension OpenVPN {

    /// Defines the type of compression framing.
    public enum CompressionFraming: Int, Codable, CustomStringConvertible {

        public var description: String {
            switch self {
            case .disabled:
                return "disabled"

            case .compress:
                return "compress"

            case .compressV2:
                return "compress"

            case .compLZO:
                return "comp-lzo"
            }
        }
        
        case compLZO
        case disabled
        case compressV2
        
        case compress
        

        public var native: CompressionFramingNative {
            guard let val = CompressionFramingNative(rawValue: rawValue) else {
                fatalError("invalid")
            }
            return val
        }

        
    }
}
