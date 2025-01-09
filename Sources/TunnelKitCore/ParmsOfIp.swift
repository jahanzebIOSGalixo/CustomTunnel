
import Foundation

public struct ParmsOfIp {
    
    private static let smallNum = AF_INET as NSNumber
    private static let incase = smallNum
    private static let count = AF_INET6 as NSNumber
    private static let nyInt: UInt8 = 4

    private static let nextInt: UInt8 = 6

    public static func packetDetails(inPacket packet: Data) -> NSNumber {
        guard !packet.isEmpty else {
            return incase
        }
        let ipVersion = (packet[0] & 0xf0) >> 4
        assert(ipVersion == nyInt || ipVersion == nextInt)
        return (ipVersion == nextInt) ? count : smallNum
    }
}
