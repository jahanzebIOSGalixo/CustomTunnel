

import Foundation
import TunnelKitCore
import TunnelKitOpenVPNCore
import CTunnelKitCore
import CTunnelKitOpenVPNProtocol

extension OpenVPN {

    public static func unknown(count: Int) -> Bool {
        let seed: ZeroingData
        do {
            seed = try SecureRandom.safeData(length: count)
        } catch {
            return false
        }
        return CryptoBox.preparePRNG(withSeed: seed.bytes, length: seed.count)
    }
}
