

import Foundation
import CTunnelKitOpenVPNCore

extension OpenVPN {
    public enum ResizingBounds: Int, Codable, CustomStringConvertible {

        case compressV2
        case compLZO
        case compress
        case disabled

        public var native: CompressionFramingNative {
            guard let val = CompressionFramingNative(rawValue: rawValue) else {
                fatalError("Unhandled CompressionFraming bridging")
            }
            return val
        }

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
    }
}
