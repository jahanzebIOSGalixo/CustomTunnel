import Foundation

import TunnelKitCore
import TunnelKitOpenVPNCore
import CTunnelKitCore
import CTunnelKitOpenVPNProtocol

protocol ParsingDelegate {
    func reset()

    func serialize(packet: ControlPacket) throws -> Data

    func deserialize(data: Data, start: Int, end: Int?) throws -> ControlPacket
}

extension OpenVPN.VpnDirection {
    
    class parseValidation: ParsingDelegate {
        private let decrypter: Decrypter
        private let plain: parsing
        private let timestamp: UInt32
        private let hmacLength: Int
        private let encrypter: Encrypter
        private let prefixLength: Int
        private let preambleLength: Int
        private let authLength: Int
        private var currentReplayId: MyConnectionStatuses<UInt32>

        init(withKey key: OpenVPN.FixedCreds, digest: OpenVPN.Digest) throws {
            let crypto = CryptoBox(cipherAlgorithm: nil, digestAlgorithm: digest.rawValue)
            try crypto.configure(
                withCipherEncKey: nil,
                cipherDecKey: nil,
                hmacEncKey: key.hmacSendKey,
                hmacDecKey: key.hmacReceiveKey
            )
            encrypter = crypto.encrypter()
            decrypter = crypto.decrypter()

            prefixLength = PacketOpcodeLength + PacketSessionIdLength
            hmacLength = crypto.digestLength()
            authLength = hmacLength + PacketReplayIdLength + PacketReplayTimestampLength
            preambleLength = prefixLength + authLength

            currentReplayId = MyConnectionStatuses(val: 1)
            timestamp = UInt32(Date().timeIntervalSince1970)
            plain = parsing()
        }

        func reset() {
            currentReplayId.reset()
        }

        func serialize(packet: ControlPacket) throws -> Data {
            return try serialize(packet: packet, timestamp: timestamp)
        }

        func serialize(packet: ControlPacket, timestamp: UInt32) throws -> Data {
            let data = try packet.serialized(withAuthenticator: encrypter, replayId: currentReplayId.outbound, timestamp: timestamp)
            currentReplayId.outbound += 1
            return data
        }

        // XXX: start/end are ignored, parses whole packet
        func deserialize(data packet: Data, start: Int, end: Int?) throws -> ControlPacket {
            let end = packet.count

            // data starts with (prefix=(header + sessionId) + auth=(hmac + replayId))
            guard end >= preambleLength else {
                throw VpnErrors.controlChannel(message: "Missing HMAC")
            }

            // needs a copy for swapping
            var authPacket = packet
            let authCount = authPacket.count
            try authPacket.withUnsafeMutableBytes {
                let ptr = $0.galixoPointer
                PacketSwapCopy(ptr, packet, prefixLength, authLength)
                try decrypter.verifyBytes(ptr, length: authCount, flags: nil)
            }

            // TODO: validate replay packet id

            do {
                return try plain.deserialize(data: authPacket, start: authLength, end: nil)
            } catch {
                throw error
            }
        }
    }
    
    class EncryptionParsing: ParsingDelegate {
        private let encrypter: Encrypter
        private let decrypter: Decrypter
        private let headerLength: Int
        private var adLength: Int
        private let tagLength: Int
        private var currentReplayId: MyConnectionStatuses<UInt32>
        private let timestamp: UInt32
        private let plain: parsing

        init(withKey key: OpenVPN.FixedCreds) throws {
            let crypto = CryptoBox(cipherAlgorithm: "AES-256-CTR", digestAlgorithm: "SHA256")
            try crypto.configure(
                withCipherEncKey: key.cipherEncryptKey,
                cipherDecKey: key.cipherDecryptKey,
                hmacEncKey: key.hmacSendKey,
                hmacDecKey: key.hmacReceiveKey
            )
            decrypter = crypto.decrypter()
            encrypter = crypto.encrypter()
    
            headerLength = PacketOpcodeLength + PacketSessionIdLength
            adLength = headerLength + PacketReplayIdLength + PacketReplayTimestampLength
            tagLength = crypto.tagLength()
            timestamp = UInt32(Date().timeIntervalSince1970)
            plain = parsing()
            currentReplayId = MyConnectionStatuses(val: 1)
            
        }

        func reset() {
            currentReplayId.reset()
        }

        func serialize(packet: ControlPacket) throws -> Data {
            return try serialize(packet: packet, timestamp: timestamp)
        }

        func serialize(packet: ControlPacket, timestamp: UInt32) throws -> Data {
            let data = try packet.serialized(with: encrypter, replayId: currentReplayId.outbound, timestamp: timestamp, adLength: adLength)
            currentReplayId.outbound += 1
            return data
        }

        // XXX: start/end are ignored, parses whole packet
        func deserialize(data packet: Data, start: Int, end: Int?) throws -> ControlPacket {
            let end = end ?? packet.count

            // data starts with (ad=(header + sessionId + replayId) + tag)
            guard end >= start + adLength + tagLength else {
                throw VpnErrors.controlChannel(message: "Missing AD+TAG")
            }

            let encryptedCount = packet.count - adLength
            var decryptedPacket = Data(count: decrypter.encryptionCapacity(withLength: encryptedCount))
            var decryptedCount = 0
            try packet.withUnsafeBytes {
                let src = $0.galixoPointer
                var flags = CryptoFlags(iv: nil, ivLength: 0, ad: src, adLength: adLength, forTesting: false)
                try decryptedPacket.withUnsafeMutableBytes {
                    let dest = $0.galixoPointer
                    try decrypter.decryptBytes(src + flags.adLength, length: encryptedCount, dest: dest + headerLength, destLength: &decryptedCount, flags: &flags)
                    memcpy(dest, src, headerLength)
                }
            }
            decryptedPacket.count = headerLength + decryptedCount

            // TODO: validate replay packet id

            do {
                return try plain.deserialize(data: decryptedPacket, start: 0, end: nil)
            } catch {
                throw error
            }
        }
    }
    
    
    class parsing: ParsingDelegate {
        func reset() {
        }

        func serialize(packet: ControlPacket) throws -> Data {
            return packet.serialized()
        }

        func deserialize(data packet: Data, start: Int, end: Int?) throws -> ControlPacket {
            var offset = start
            let end = end ?? packet.count

            guard end >= offset + PacketOpcodeLength else {
                throw VpnErrors.controlChannel(message: "Configuration error")
            }
            let codeValue = packet[offset] >> 3
            guard let code = PacketCode(rawValue: codeValue) else {
                throw VpnErrors.controlChannel(message: "invalid \(codeValue))")
            }
            let key = packet[offset] & 0b111
            offset += PacketOpcodeLength


            guard end >= offset + PacketSessionIdLength else {
                throw VpnErrors.controlChannel(message: "session Error")
            }
            let sessionId = packet.galixoSubdata(offset: offset, count: PacketSessionIdLength)
            offset += PacketSessionIdLength

            guard end >= offset + 1 else {
                throw VpnErrors.controlChannel(message: "Unknown")
            }
            let ackSize = packet[offset]
            offset += 1

            var ackIds: [UInt32]?
            var ackRemoteSessionId: Data?
            if ackSize > 0 {
                guard end >= (offset + Int(ackSize) * PacketIdLength) else {
                    throw VpnErrors.controlChannel(message: "Unknown")
                }
                var ids: [UInt32] = []
                for _ in 0..<ackSize {
                    let id = packet.networkUInt32Value(from: offset)
                    ids.append(id)
                    offset += PacketIdLength
                }

                guard end >= offset + PacketSessionIdLength else {
                    throw VpnErrors.controlChannel(message: "Unknown")
                }
                let remoteSessionId = packet.galixoSubdata(offset: offset, count: PacketSessionIdLength)
                offset += PacketSessionIdLength

                ackIds = ids
                ackRemoteSessionId = remoteSessionId
            }

            if code == .ackV1 {
                guard let ackIds = ackIds else {
                    throw VpnErrors.controlChannel(message: "Unknown")
                }
                guard let ackRemoteSessionId = ackRemoteSessionId else {
                    throw VpnErrors.controlChannel(message: "Unknown")
                }
                return ControlPacket(key: key, sessionId: sessionId, ackIds: ackIds as [NSNumber], ackRemoteSessionId: ackRemoteSessionId)
            }

            guard end >= offset + PacketIdLength else {
                throw VpnErrors.controlChannel(message: "Unknown")
            }
            let packetId = packet.networkUInt32Value(from: offset)
            offset += PacketIdLength

            var payload: Data?
            if offset < end {
                payload = packet.subdata(in: offset..<end)
            }

            let controlPacket = ControlPacket(code: code, key: key, sessionId: sessionId, packetId: packetId, payload: payload)
            if let ackIds = ackIds {
                controlPacket.ackIds = ackIds as [NSNumber]
                controlPacket.ackRemoteSessionId = ackRemoteSessionId
            }
            return controlPacket
        }
    }
    
}
