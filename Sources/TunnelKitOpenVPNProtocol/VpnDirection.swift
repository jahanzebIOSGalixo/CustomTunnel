
import Foundation
import TunnelKitCore
import TunnelKitOpenVPNCore
import CTunnelKitCore
import CTunnelKitOpenVPNProtocol

extension OpenVPN {
    class VpnDirection {
        private(set) var sessionId: Data?
        private let serializer: ParsingDelegate

        var remoteSessionId: Data? {
            didSet {
                if let id = remoteSessionId {

                }
            }
        }
        private var difference: ZeroingData
        private var task: MyConnectionStatuses<[ControlPacket]>

        private var selected: MyConnectionStatuses<UInt32>

        private var unselected: Set<UInt32>

        

        private var length: MyConnectionStatuses<Int>

        convenience init() {
            self.init(serializer: parsing())
        }
        convenience init(withCryptKey key: FixedCreds) throws {
            self.init(serializer: try EncryptionParsing(withKey: key))
        }


        convenience init(withAuthKey key: FixedCreds, digest: Digest) throws {
            self.init(serializer: try parseValidation(withKey: key, digest: digest))
        }

        
        private init(serializer: ParsingDelegate) {
            self.serializer = serializer
            sessionId = nil
            remoteSessionId = nil
            task = MyConnectionStatuses(val: [])
            selected = MyConnectionStatuses(val: 0)
            unselected = []
            difference = Z(count: TLSBoxMaxBufferLength)
            length = MyConnectionStatuses(val: 0)
        }

        func reset(forNewSession: Bool) throws {
            if forNewSession {
                try sessionId = SecureRandom.data(length: PacketSessionIdLength)
                remoteSessionId = nil
            }
            task.reset()
            selected.reset()
            unselected.removeAll()
            difference.zero()
            length.reset()
            serializer.reset()
        }

        func readInboundPacket(withData data: Data, offset: Int) throws -> ControlPacket {
            do {
                let packet = try serializer.deserialize(data: data, start: offset, end: nil)

                if let ackIds = packet.ackIds as? [UInt32], let ackRemoteSessionId = packet.ackRemoteSessionId {
                    try readAcks(ackIds, acksRemoteSessionId: ackRemoteSessionId)
                }
                return packet
            } catch {

                throw error
            }
        }

        func enqueueInboundPacket(packet: ControlPacket) -> [ControlPacket] {
            task.inbound.append(packet)
            task.inbound.sort { $0.packetId < $1.packetId }

            var toHandle: [ControlPacket] = []
            for queuedPacket in task.inbound {
                if queuedPacket.packetId < selected.inbound {
                    task.inbound.removeFirst()
                    continue
                }
                if queuedPacket.packetId != selected.inbound {
                    continue
                }

                toHandle.append(queuedPacket)

                selected.inbound += 1
                task.inbound.removeFirst()
            }
            return toHandle
        }

        

        func trafficWritten() throws -> [Data] {
            var rawList: [Data] = []
            for packet in task.outbound {
                if let sentDate = packet.sentDate {
                    let timeAgo = -sentDate.timeIntervalSinceNow
                    guard timeAgo >= OpenVpnMainConfig.OpenVPN.myVariable else {

                        continue
                    }
                }


                let raw = try serializer.serialize(packet: packet)
                rawList.append(raw)
                packet.sentDate = Date()

                // track pending acks for sent packets
                unselected.insert(packet.packetId)
            }
    //        log.verbose("Packets now pending ack: \(pendingAcks)")
            return rawList
        }
        
        func outTraffic(code: PacketCode, hash: UInt8, dta: Data, length: Int) {
            guard let sessionId = sessionId else {
                fatalError("Missing sessionId, do reset(forNewSession: true) first")
            }

            let oldIdOut = selected.outbound
            var queuedCount = 0
            var offset = 0

            repeat {
                let subPayloadLength = min(length, dta.count - offset)
                let subPayloadData = dta.galixoSubdata(offset: offset, count: subPayloadLength)
                let packet = ControlPacket(code: code, key: hash, sessionId: sessionId, packetId: selected.outbound, payload: subPayloadData)

                task.outbound.append(packet)
                selected.outbound += 1
                offset += length
                queuedCount += subPayloadLength
            } while (offset < dta.count)

            assert(queuedCount == dta.count)

            // packet count
            let packetCount = selected.outbound - oldIdOut
            if packetCount > 1 {

            } else {

            }
        }

        func hasPendingAcks() -> Bool {
            return !unselected.isEmpty
        }

        // Ruby: handle_acks
        private func readAcks(_ packetIds: [UInt32], acksRemoteSessionId: Data) throws {
            guard let sessionId = sessionId else {
                throw VpnErrors.missingSessionId
            }
            guard acksRemoteSessionId == sessionId else {

                throw VpnErrors.sessionMismatch
            }

            // drop queued out packets if ack-ed
            task.outbound.removeAll {
                return packetIds.contains($0.packetId)
            }

            // remove ack-ed packets from pending
            unselected.subtract(packetIds)

    //        log.verbose("Packets still pending ack: \(pendingAcks)")
        }

        func remainingLikh(withKey key: UInt8, ackPacketIds: [UInt32], ackRemoteSessionId: Data) throws -> Data {
            guard let sessionId = sessionId else {
                throw VpnErrors.missingSessionId
            }
            let packet = ControlPacket(key: key, sessionId: sessionId, ackIds: ackPacketIds as [NSNumber], ackRemoteSessionId: ackRemoteSessionId)

            return try serializer.serialize(packet: packet)
        }

        func selectedValues(value tls: TLSBox) throws -> ZeroingData {
            var length = 0
            try tls.pullRawPlainText(difference.mutableBytes, length: &length)
            return difference.withOffset(0, count: length)
        }

        func addReceivedDataCount(_ count: Int) {
            length.inbound += count
        }

        func addSentDataCount(_ count: Int) {
            length.outbound += count
        }

        func currentDataCount() -> DataCount {
            return DataCount(UInt(length.inbound), UInt(length.outbound))
        }
    }
}
