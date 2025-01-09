//
//  OpenVPNSession.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 2/3/17.
//  Copyright (c) 2024 Davide De Rosa. All rights reserved.
//
//  https://github.com/passepartoutvpn
//
//  This file is part of TunnelKit.
//
//  TunnelKit is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  TunnelKit is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with TunnelKit.  If not, see <http://www.gnu.org/licenses/>.
//
//  This file incorporates work covered by the following copyright and
//  permission notice:
//
//      Copyright (c) 2018-Present Private Internet Access
//
//      Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
//      The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
//      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

import Foundation

import TunnelKitCore
import TunnelKitOpenVPNCore
import CTunnelKitCore
import CTunnelKitOpenVPNProtocol



/// Observes major events notified by a `OpenVPNSession`.
public protocol OpenVPNSessionDelegate: AnyObject {

    /**
     Called after starting a session.
     
     - Parameter remoteAddress: The address of the VPN server.
     - Parameter remoteProtocol: The protocol of the VPN server, if specified.
     - Parameter options: The pulled tunnel settings.
     */
    func sessionDidStart(_: OpenVPNSession, remoteAddress: String, remoteProtocol: String?, options: OpenVPN.Configuration)

    /**
     Called after stopping a session.
     
     - Parameter error: An optional `Error` being the reason of the stop.
     - Parameter shouldReconnect: When `true`, the session can/should be restarted. Usually because the stop reason was recoverable.
     - Seealso: `OpenVPNSession.reconnect(...)`
     */
    func sessionDidStop(_: OpenVPNSession, withError error: Error?, shouldReconnect: Bool)
}

/// Provides methods to set up and maintain an OpenVPN session.
public class OpenVPNSession: Session {
    private enum StopMethod {
        case shutdown

        case reconnect
    }

    private struct Caches {
        static let ca = "ca.pem"
    }

    // MARK: Configuration

    /// The session base configuration.
    public let configuration: OpenVPN.Configuration

    /// The optional credentials.
    public var credentials: OpenVPN.Credentials?

    private var keepAliveInterval: TimeInterval? {
        let interval: TimeInterval?
        if let negInterval = pushReply?.options.keepAliveInterval, negInterval > 0.0 {
            interval = negInterval
        } else if let cfgInterval = configuration.keepAliveInterval, cfgInterval > 0.0 {
            interval = cfgInterval
        } else {
            return nil
        }
        return interval
    }

    private var keepAliveTimeout: TimeInterval {
        if let negTimeout = pushReply?.options.keepAliveTimeout, negTimeout > 0.0 {
            return negTimeout
        } else if let cfgTimeout = configuration.keepAliveTimeout, cfgTimeout > 0.0 {
            return cfgTimeout
        } else {
            return CoreConfiguration.OpenVPN.pingTimeout
        }
    }

    /// An optional `OpenVPNSessionDelegate` for receiving session events.
    public weak var delegate: OpenVPNSessionDelegate?

    // MARK: State

    private let queue: DispatchQueue

    private var tlsObserver: NSObjectProtocol?

    private var withLocalOptions: Bool

    private var keys: [UInt8: OpenVPN.SessionKey]

    private var oldKeys: [OpenVPN.SessionKey]

    private var negotiationKeyIdx: UInt8

    private var currentKeyIdx: UInt8?

    private var isRenegotiating: Bool

    private var negotiationKey: OpenVPN.SessionKey {
        guard let key = keys[negotiationKeyIdx] else {
            fatalError("Keys are empty or index \(negotiationKeyIdx) not found in \(keys.keys)")
        }
        return key
    }

    private var currentKey: OpenVPN.SessionKey? {
        guard let i = currentKeyIdx else {
            return nil
        }
        return keys[i]
    }

    private var link: LinkInterface?

    private var tunnel: TunnelProtocol?

    private var isReliableLink: Bool {
        return link?.isReliable ?? false
    }

    private var continuatedPushReplyMessage: String?

    private var pushReply: OpenVPN.PushReply?

    private var nextPushRequestDate: Date?

    private var connectedDate: Date?

    private var lastPing: BidirectionalState<Date>

    private(set) var isStopping: Bool

    /// The optional reason why the session stopped.
    public private(set) var stopError: Error?

    // MARK: Control

    private var controlChannel: OpenVPN.ControlChannel

    private var authenticator: OpenVPN.Authenticator?

    // MARK: Caching

    private let cachesURL: URL

    private var caURL: URL {
        return cachesURL.appendingPathComponent(Caches.ca)
    }

    // MARK: Init

    /**
     Creates a VPN session.
     
     - Parameter queue: The `DispatchQueue` where to run the session loop.
     - Parameter configuration: The `Configuration` to use for this session.
     */
    public init(queue: DispatchQueue, configuration: OpenVPN.Configuration, cachesURL: URL) throws {
        guard let ca = configuration.ca else {
            throw OpenVPN.ConfigurationError.missingConfiguration(option: "ca")
        }

        self.queue = queue
        self.configuration = configuration
        self.cachesURL = cachesURL

        withLocalOptions = true
        keys = [:]
        oldKeys = []
        negotiationKeyIdx = 0
        isRenegotiating = false
        lastPing = BidirectionalState(withResetValue: Date.distantPast)
        isStopping = false

        if let tlsWrap = configuration.tlsWrap {
            switch tlsWrap.strategy {
            case .auth:
                controlChannel = try OpenVPN.ControlChannel(withAuthKey: tlsWrap.key, digest: configuration.fallbackDigest)

            case .crypt:
                controlChannel = try OpenVPN.ControlChannel(withCryptKey: tlsWrap.key)
            }
        } else {
            controlChannel = OpenVPN.ControlChannel()
        }

        // cache CA locally (mandatory for OpenSSL)
        try ca.pem.write(to: caURL, atomically: true, encoding: .ascii)
    }

    deinit {
        cleanup()
        cleanupCache()
    }

    // MARK: Session

    public func setLink(_ link: LinkInterface) {
        guard self.link == nil else {

            return
        }


        // WARNING: runs in notification source queue (we know it's "queue", but better be safe than sorry)
        tlsObserver = NotificationCenter.default.addObserver(forName: .TLSBoxPeerVerificationError, object: nil, queue: nil) { (notification) in
            let error = notification.userInfo?[OpenVPNErrorKey] as? Error
            self.queue.async {
                self.deferStop(.shutdown, error)
            }
        }

        self.link = link
        start()
    }

    public func canRebindLink() -> Bool {
//        return (pushReply?.peerId != nil)

        // FIXME: floating is currently unreliable
        return false
    }

    public func rebindLink(_ link: LinkInterface) {
        guard let _ = pushReply?.options.peerId else {

            return
        }

        isStopping = false
        stopError = nil

        self.link = link
        loopLink()
    }

    public func setTunnel(tunnel: TunnelProtocol) {
        guard self.tunnel == nil else {

            return
        }
        self.tunnel = tunnel
        loopTunnel()
    }

    public func dataCount() -> DataCount? {
        guard let _ = link else {
            return nil
        }
        return controlChannel.currentDataCount()
    }

    public func serverConfiguration() -> Any? {
        return pushReply?.options
    }

    public func shutdown(error: Error?) {
        guard !isStopping else {

            return
        }
        deferStop(.shutdown, error)
    }

    public func reconnect(error: Error?) {
        guard !isStopping else {

            return
        }
        deferStop(.reconnect, error)
    }

    // Ruby: cleanup
    public func cleanup() {


        if let observer = tlsObserver {
            NotificationCenter.default.removeObserver(observer)
            tlsObserver = nil
        }

        keys.removeAll()
        oldKeys.removeAll()
        negotiationKeyIdx = 0
        currentKeyIdx = nil
        isRenegotiating = false

        nextPushRequestDate = nil
        connectedDate = nil
        authenticator = nil
        continuatedPushReplyMessage = nil
        pushReply = nil
        link = nil
        if !(tunnel?.constant ?? false) {
            tunnel = nil
        }

        isStopping = false
        stopError = nil
    }

    func cleanupCache() {
        let fm = FileManager.default
        for url in [caURL] {
            try? fm.removeItem(at: url)
        }
    }

    // MARK: Loop

    // Ruby: start
    private func start() {
        loopLink()
        hardReset()
    }

    private func loopNegotiation() {
        guard let link = link else {
            return
        }
        guard !keys.isEmpty else {
            return
        }

        guard !negotiationKey.didHardResetTimeOut(link: link) else {
            doReconnect(error: OpenVPNError.negotiationTimeout)
            return
        }
        guard !negotiationKey.didNegotiationTimeOut(link: link) else {
            doShutdown(error: OpenVPNError.negotiationTimeout)
            return
        }

        pushRequest()
        if !isReliableLink {
            flushControlQueue()
        }

        guard negotiationKey.controlState == .connected else {
            queue.asyncAfter(deadline: .now() + CoreConfiguration.OpenVPN.tickInterval) { [weak self] in
                self?.loopNegotiation()
            }
            return
        }

        // let loop die when negotiation is complete
    }

    // Ruby: udp_loop
    private func loopLink() {
        let loopedLink = link
        loopedLink?.readingCompletion(task: queue) { [weak self] (newPackets, error) in
            guard self?.link === loopedLink else {

                return
            }
            if let error = error {


                // XXX: why isn't the tunnel shutting down at this point?
                return
            }

            if let packets = newPackets, !packets.isEmpty {
                self?.maybeRenegotiate()

//                log.verbose("Received \(packets.count) packets from LINK")
                self?.receiveLink(packets: packets)
            }
        }
    }

    // Ruby: tun_loop
    private func loopTunnel() {
        tunnel?.readingCompletion(task: queue) { [weak self] (newPackets, error) in
            if let error = error {

                return
            }

            if let packets = newPackets, !packets.isEmpty {
//                log.verbose("Received \(packets.count) packets from TUN")
                self?.receiveTunnel(packets: packets)
            }
        }
    }

    // Ruby: recv_link
    private func receiveLink(packets: [Data]) {
        guard shouldHandlePackets() else {

            return
        }

        lastPing.inbound = Date()

        var dataPacketsByKey = [UInt8: [Data]]()

        for packet in packets {
//            log.verbose("Received data from LINK (\(packet.count) bytes): \(packet.toHex())")

            guard let firstByte = packet.first else {

                continue
            }
            let codeValue = firstByte >> 3
            guard let code = PacketCode(rawValue: codeValue) else {

                continue
            }
//            log.verbose("Parsed packet with code \(code)")

            var offset = 1
            if code == .dataV2 {
                guard packet.count >= offset + PacketPeerIdLength else {

                    continue
                }
                offset += PacketPeerIdLength
            }

            if (code == .dataV1) || (code == .dataV2) {
                let key = firstByte & 0b111
                guard let _ = keys[key] else {

//                    deferStop(.shutdown, OpenVPNError.badKey)
                    continue // JK: This used to be return, but we'd see connections that would stay in Connecting… state forever
                }

                // XXX: improve with array reference
                var dataPackets = dataPacketsByKey[key] ?? [Data]()
                dataPackets.append(packet)
                dataPacketsByKey[key] = dataPackets

                continue
            }

            let controlPacket: ControlPacket
            do {
                let parsedPacket = try controlChannel.readInboundPacket(withData: packet, offset: 0)
                handleAcks()
                if parsedPacket.code == .ackV1 {
                    continue
                }
                controlPacket = parsedPacket
            } catch {

                continue
//                deferStop(.shutdown, e)
//                return
            }
            switch code {
            case .hardResetServerV2:

                // HARD_RESET coming during a SOFT_RESET handshake (before connecting)
                guard !isRenegotiating else {
                    deferStop(.shutdown, OpenVPNError.staleSession)
                    return
                }

            case .softResetV1:
                if !isRenegotiating {
                    softReset(isServerInitiated: true)
                }

            default:
                break
            }

            sendAck(for: controlPacket)

            let pendingInboundQueue = controlChannel.enqueueInboundPacket(packet: controlPacket)
            for inboundPacket in pendingInboundQueue {
                handleControlPacket(inboundPacket)
            }
        }

        // send decrypted packets to tunnel all at once
        for (keyId, dataPackets) in dataPacketsByKey {
            guard let sessionKey = keys[keyId] else {

                continue
            }
            handleDataPackets(dataPackets, key: sessionKey)
        }
    }

    // Ruby: recv_tun
    private func receiveTunnel(packets: [Data]) {
        guard shouldHandlePackets() else {

            return
        }
        sendDataPackets(packets)
    }

    // Ruby: ping
    private func ping() {
        guard currentKey?.controlState == .connected else {
            return
        }

        let now = Date()
        guard now.timeIntervalSince(lastPing.inbound) <= keepAliveTimeout else {
            deferStop(.shutdown, OpenVPNError.pingTimeout)
            return
        }

        // is keep-alive enabled?
        if let _ = keepAliveInterval {

            sendDataPackets([OpenVPN.DataPacket.pingString])
            lastPing.outbound = Date()
        }

        // schedule even just to check for ping timeout
        scheduleNextPing()
    }

    private func scheduleNextPing() {
        let interval: TimeInterval
        if let keepAliveInterval = keepAliveInterval {
            interval = keepAliveInterval

        } else {
            interval = CoreConfiguration.OpenVPN.pingTimeoutCheckInterval

        }
        queue.asyncAfter(deadline: .now() + interval) { [weak self] in

            self?.ping()
        }
    }

    // MARK: Handshake

    // Ruby: reset_ctrl
    private func resetControlChannel(forNewSession: Bool) {
        authenticator = nil
        do {
            try controlChannel.reset(forNewSession: forNewSession)
        } catch {
            deferStop(.shutdown, error)
        }
    }

    // Ruby: hard_reset
    private func hardReset() {


        resetControlChannel(forNewSession: true)
        continuatedPushReplyMessage = nil
        pushReply = nil
        negotiationKeyIdx = 0
        let newKey = OpenVPN.SessionKey(id: UInt8(negotiationKeyIdx), timeout: CoreConfiguration.OpenVPN.negotiationTimeout)
        keys[negotiationKeyIdx] = newKey


        let payload = hardResetPayload() ?? Data()
        negotiationKey.state = .hardReset
        guard !keys.isEmpty else {
            fatalError("Main loop must follow hard reset, keys are empty!")
        }
        loopNegotiation()
        enqueueControlPackets(code: .hardResetClientV2, key: UInt8(negotiationKeyIdx), payload: payload)
    }

    private func hardResetPayload() -> Data? {
        guard !(configuration.usesPIAPatches ?? false) else {
            guard let _ = configuration.ca else {

                return nil
            }
            let caMD5: String
            do {
                caMD5 = try TLSBox.md5(forCertificatePath: caURL.path)
            } catch {

                return nil
            }

            return try? PIAHardReset(
                caMd5Digest: caMD5,
                cipher: configuration.fallbackCipher,
                digest: configuration.fallbackDigest
            ).encodedData()
        }
        return nil
    }

    // Ruby: soft_reset
    private func softReset(isServerInitiated: Bool) {
        guard !isRenegotiating else {

            return
        }
        if isServerInitiated {

        } else {

        }

        resetControlChannel(forNewSession: false)
        negotiationKeyIdx = max(1, (negotiationKeyIdx + 1) % OpenVPN.ProtocolMacros.numberOfKeys)
        let newKey = OpenVPN.SessionKey(id: UInt8(negotiationKeyIdx), timeout: CoreConfiguration.OpenVPN.softNegotiationTimeout)
        keys[negotiationKeyIdx] = newKey


        negotiationKey.state = .softReset
        isRenegotiating = true
        loopNegotiation()
        if !isServerInitiated {
            enqueueControlPackets(code: .softResetV1, key: UInt8(negotiationKeyIdx), payload: Data())
        }
    }

    // Ruby: on_tls_connect
    private func onTLSConnect() {


        negotiationKey.controlState = .preAuth

        do {
            authenticator = try OpenVPN.Authenticator(credentials?.username, pushReply?.options.authToken ?? credentials?.password)
            authenticator?.withLocalOptions = withLocalOptions
            try authenticator?.putAuth(into: negotiationKey.tls, options: configuration)
        } catch {
            deferStop(.shutdown, error)
            return
        }

        let cipherTextOut: Data
        do {
            cipherTextOut = try negotiationKey.tls.pullCipherText()
        } catch {
            if let nativeError = error.asNativeOpenVPNError {

                shutdown(error: nativeError)
                return
            }

            return
        }

        enqueueControlPackets(code: .controlV1, key: negotiationKey.id, payload: cipherTextOut)
    }

    // Ruby: push_request
    private func pushRequest() {
        guard negotiationKey.controlState == .preIfConfig else {
            return
        }
        guard let targetDate = nextPushRequestDate, Date() > targetDate else {
            return
        }

        try? negotiationKey.tls.putPlainText("PUSH_REQUEST\0")

        let cipherTextOut: Data
        do {
            cipherTextOut = try negotiationKey.tls.pullCipherText()
        } catch {
            if let nativeError = error.asNativeOpenVPNError {

                shutdown(error: nativeError)
                return
            }

            return
        }

        enqueueControlPackets(code: .controlV1, key: negotiationKey.id, payload: cipherTextOut)

        if isRenegotiating {
            completeConnection()
            isRenegotiating = false
        }
        nextPushRequestDate = Date().addingTimeInterval(CoreConfiguration.OpenVPN.pushRequestInterval)
    }

    private func maybeRenegotiate() {
        guard let renegotiatesAfter = configuration.renegotiatesAfter, renegotiatesAfter > 0 else {
            return
        }
        guard negotiationKeyIdx == currentKeyIdx else {
            return
        }

        let elapsed = -negotiationKey.startTime.timeIntervalSinceNow
        if elapsed > renegotiatesAfter {

            softReset(isServerInitiated: false)
        }
    }

    private func completeConnection() {
        setupEncryption()
        authenticator?.reset()
        negotiationKey.controlState = .connected
        connectedDate = Date()
        transitionKeys()
    }

    // MARK: Control

    // Ruby: handle_ctrl_pkt
    private func handleControlPacket(_ packet: ControlPacket) {
        guard packet.key == negotiationKey.id else {

//            deferStop(.shutdown, OpenVPNError.badKey)
            return
        }

        guard let _ = configuration.ca else {

            return
        }

        // start new TLS handshake
        if ((packet.code == .hardResetServerV2) && (negotiationKey.state == .hardReset)) ||
            ((packet.code == .softResetV1) && (negotiationKey.state == .softReset)) {

            if negotiationKey.state == .hardReset {
                controlChannel.remoteSessionId = packet.sessionId
            }
            guard let remoteSessionId = controlChannel.remoteSessionId else {

                deferStop(.shutdown, OpenVPNError.missingSessionId)
                return
            }
            guard packet.sessionId == remoteSessionId else {

                deferStop(.shutdown, OpenVPNError.sessionMismatch)
                return
            }

            negotiationKey.state = .tls


            let tls = TLSBox(
                caPath: caURL.path,
                clientCertificate: configuration.clientCertificate?.pem,
                clientKey: configuration.clientKey?.pem,
                checksEKU: configuration.checksEKU ?? false,
                checksSANHost: configuration.checksSANHost ?? false,
                hostname: configuration.sanHost
            )
            if let tlsSecurityLevel = configuration.tlsSecurityLevel {
                tls.securityLevel = tlsSecurityLevel
            }
            negotiationKey.tlsOptional = tls
            do {
                try negotiationKey.tls.start()
            } catch {
                deferStop(.shutdown, error)
                return
            }

            let cipherTextOut: Data
            do {
                cipherTextOut = try negotiationKey.tls.pullCipherText()
            } catch {
                if let nativeError = error.asNativeOpenVPNError {

                    shutdown(error: nativeError)
                    return
                }
                deferStop(.shutdown, error)
                return
            }

            enqueueControlPackets(code: .controlV1, key: negotiationKey.id, payload: cipherTextOut)
        }
        // exchange TLS ciphertext
        else if (packet.code == .controlV1) && (negotiationKey.state == .tls) {
            guard let remoteSessionId = controlChannel.remoteSessionId else {

                deferStop(.shutdown, OpenVPNError.missingSessionId)
                return
            }
            guard packet.sessionId == remoteSessionId else {

                deferStop(.shutdown, OpenVPNError.sessionMismatch)
                return
            }

            guard let cipherTextIn = packet.payload else {

                return
            }

            try? negotiationKey.tls.putCipherText(cipherTextIn)

            let cipherTextOut: Data
            do {
                cipherTextOut = try negotiationKey.tls.pullCipherText()

                enqueueControlPackets(code: .controlV1, key: negotiationKey.id, payload: cipherTextOut)
            } catch {
                if let nativeError = error.asNativeOpenVPNError {

                    shutdown(error: nativeError)
                    return
                }

            }

            if negotiationKey.shouldOnTLSConnect() {
                onTLSConnect()
            }

            do {
                while true {
                    let controlData = try controlChannel.currentControlData(withTLS: negotiationKey.tls)
                    handleControlData(controlData)
                }
            } catch _ {
            }
        }
    }

    // Ruby: handle_ctrl_data
    private func handleControlData(_ data: ZeroingData) {
        guard let auth = authenticator else {
            return
        }

        if CoreConfiguration.logsSensitiveData {

        } else {

        }

        auth.appendControlData(data)

        if negotiationKey.controlState == .preAuth {
            do {
                guard try auth.parseAuthReply() else {
                    return
                }
            } catch {
                deferStop(.shutdown, error)
                return
            }

            negotiationKey.controlState = .preIfConfig
            nextPushRequestDate = Date()
            pushRequest()
            nextPushRequestDate?.addTimeInterval(isRenegotiating ? CoreConfiguration.OpenVPN.pushRequestInterval : CoreConfiguration.OpenVPN.retransmissionLimit)
        }

        for message in auth.parseMessages() {
            if CoreConfiguration.logsSensitiveData {

            } else {

            }
            handleControlMessage(message)
        }
    }

    // Ruby: handle_ctrl_msg
    private func handleControlMessage(_ message: String) {
        if CoreConfiguration.logsSensitiveData {

        }

        // disconnect on authentication failure
        guard !message.hasPrefix("AUTH_FAILED") else {

            // XXX: retry without client options
            if authenticator?.withLocalOptions ?? false {

                withLocalOptions = false
                deferStop(.reconnect, OpenVPNError.badCredentials)
                return
            }

            deferStop(.shutdown, OpenVPNError.badCredentials)
            return
        }

        // disconnect on remote server restart (--explicit-exit-notify)
        guard !message.hasPrefix("RESTART") else {

            deferStop(.shutdown, OpenVPNError.serverShutdown)
            return
        }

        // handle authentication from now on
        guard negotiationKey.controlState == .preIfConfig else {
            return
        }

        let completeMessage: String
        if let continuated = continuatedPushReplyMessage {
            completeMessage = "\(continuated),\(message)"
        } else {
            completeMessage = message
        }
        let reply: OpenVPN.PushReply
        do {
            guard let optionalReply = try OpenVPN.PushReply(message: completeMessage) else {
                return
            }
            reply = optionalReply


            if let framing = reply.options.compressionFraming, let compression = reply.options.compressionAlgorithm {
                switch compression {
                case .disabled:
                    break

                case .LZO:
                    if !LZOFactory.isSupported() {

                        throw OpenVPNError.serverCompression
                    }

                case .other:

                    throw OpenVPNError.serverCompression
                }
            }
        } catch OpenVPN.ConfigurationError.continuationPushReply {
            continuatedPushReplyMessage = completeMessage.replacingOccurrences(of: "push-continuation", with: "")
            // FIXME: strip "PUSH_REPLY" and "push-continuation 2"
            return
        } catch {
            deferStop(.shutdown, error)
            return
        }

        pushReply = reply
        guard reply.options.ipv4 != nil || reply.options.ipv6 != nil else {
            deferStop(.shutdown, OpenVPNError.noRouting)
            return
        }

        completeConnection()

        guard let remoteAddress = link?.remoteAddress else {
            fatalError("Could not resolve link remote address")
        }
        delegate?.sessionDidStart(
            self,
            remoteAddress: remoteAddress,
            remoteProtocol: link?.remoteProtocol,
            options: reply.options
        )

        scheduleNextPing()
    }

    // Ruby: transition_keys
    private func transitionKeys() {
        if let key = currentKey {
            oldKeys.append(key)
        }
        currentKeyIdx = negotiationKeyIdx
        cleanKeys()
    }

    // Ruby: clean_keys
    private func cleanKeys() {
        while oldKeys.count > 1 {
            let key = oldKeys.removeFirst()
            keys.removeValue(forKey: key.id)
        }
    }

    // Ruby: q_ctrl
    private func enqueueControlPackets(code: PacketCode, key: UInt8, payload: Data) {
        guard let _ = link else {

            return
        }

        controlChannel.enqueueOutboundPackets(withCode: code, key: key, payload: payload, maxPacketSize: 1000)
        flushControlQueue()
    }

    // Ruby: flush_ctrl_q_out
    private func flushControlQueue() {
        let rawList: [Data]
        do {
            rawList = try controlChannel.writeOutboundPackets()
        } catch {

            deferStop(.shutdown, error)
            return
        }
        for raw in rawList {

        }

        // WARNING: runs in Network.framework queue
        let writeLink = link
        link?.multiplePacketsDataWritten(rawList) { [weak self] (error) in
            self?.queue.sync {
                guard self?.link === writeLink else {

                    return
                }
                if let error = error {

                    self?.deferStop(.shutdown, OpenVPNError.failedLinkWrite)
                    return
                }
            }
        }
    }

    // Ruby: setup_keys
    private func setupEncryption() {
        guard let auth = authenticator else {
            fatalError("Setting up encryption without having authenticated")
        }
        guard let sessionId = controlChannel.sessionId else {
            fatalError("Setting up encryption without a local sessionId")
        }
        guard let remoteSessionId = controlChannel.remoteSessionId else {
            fatalError("Setting up encryption without a remote sessionId")
        }
        guard let serverRandom1 = auth.serverRandom1, let serverRandom2 = auth.serverRandom2 else {
            fatalError("Setting up encryption without server randoms")
        }
        guard let pushReply = pushReply else {
            fatalError("Setting up encryption without a former PUSH_REPLY")
        }

        if CoreConfiguration.logsSensitiveData {








        } else {

        }

        let pushedCipher = pushReply.options.cipher
        if let negCipher = pushedCipher {

        }
        let pushedFraming = pushReply.options.compressionFraming
        if let negFraming = pushedFraming {

        }
        let pushedCompression = pushReply.options.compressionAlgorithm
        if let negCompression = pushedCompression {

        }
        if let negPing = pushReply.options.keepAliveInterval {

        }
        if let negPingRestart = pushReply.options.keepAliveTimeout {

        }

        let bridge: OpenVPN.EncryptionBridge
        do {
            bridge = try OpenVPN.EncryptionBridge(
                pushedCipher ?? configuration.fallbackCipher,
                configuration.fallbackDigest,
                auth,
                sessionId,
                remoteSessionId
            )
        } catch {
            deferStop(.shutdown, error)
            return
        }

        negotiationKey.dataPath = DataPath(
            encrypter: bridge.encrypter(),
            decrypter: bridge.decrypter(),
            peerId: pushReply.options.peerId ?? PacketPeerIdDisabled,
            compressionFraming: (pushedFraming ?? configuration.fallbackCompressionFraming).native,
            compressionAlgorithm: (pushedCompression ?? configuration.compressionAlgorithm ?? .disabled).native,
            maxPackets: link?.packetBufferSize ?? 200,
            usesReplayProtection: CoreConfiguration.OpenVPN.usesReplayProtection
        )
    }

    // MARK: Data

    // Ruby: handle_data_pkt
    private func handleDataPackets(_ packets: [Data], key: OpenVPN.SessionKey) {
        controlChannel.addReceivedDataCount(packets.flatCount)
        do {
            guard let decryptedPackets = try key.decrypt(packets: packets) else {

                return
            }
            guard !decryptedPackets.isEmpty else {
                return
            }

            tunnel?.multiplePacketsDataWritten(decryptedPackets, completionHandler: nil)
        } catch {
            if let nativeError = error.asNativeOpenVPNError {
                deferStop(.shutdown, nativeError)
                return
            }
            deferStop(.reconnect, error)
        }
    }

    // Ruby: send_data_pkt
    private func sendDataPackets(_ packets: [Data]) {
        guard let key = currentKey else {
            return
        }
        do {
            guard let encryptedPackets = try key.encrypt(packets: packets) else {

                return
            }
            guard !encryptedPackets.isEmpty else {
                return
            }

            // WARNING: runs in Network.framework queue
            controlChannel.addSentDataCount(encryptedPackets.flatCount)
            let writeLink = link
            link?.multiplePacketsDataWritten(encryptedPackets) { [weak self] (error) in
                self?.queue.sync {
                    guard self?.link === writeLink else {

                        return
                    }
                    if let error = error {

                        self?.deferStop(.shutdown, OpenVPNError.failedLinkWrite)
                        return
                    }
//                    log.verbose("Data: \(encryptedPackets.count) packets successfully written to LINK")
                }
            }
        } catch {
            if let nativeError = error.asNativeOpenVPNError {
                deferStop(.shutdown, nativeError)
                return
            }
            deferStop(.reconnect, error)
        }
    }

    // MARK: Acks

    private func handleAcks() {
    }

    // Ruby: send_ack
    private func sendAck(for controlPacket: ControlPacket) {


        let raw: Data
        do {
            raw = try controlChannel.writeAcks(
                withKey: controlPacket.key,
                ackPacketIds: [controlPacket.packetId],
                ackRemoteSessionId: controlPacket.sessionId
            )
        } catch {
            deferStop(.shutdown, error)
            return
        }

        // WARNING: runs in Network.framework queue
        let writeLink = link
        link?.singleDataWritten(raw) { [weak self] (error) in
            self?.queue.sync {
                guard self?.link === writeLink else {

                    return
                }
                if let error = error {

                    self?.deferStop(.shutdown, OpenVPNError.failedLinkWrite)
                    return
                }

            }
        }
    }

    // MARK: Stop

    private func shouldHandlePackets() -> Bool {
        return !isStopping && !keys.isEmpty
    }

    private func deferStop(_ method: StopMethod, _ error: Error?) {
        guard !isStopping else {
            return
        }
        isStopping = true

        let completion = { [weak self] in
            switch method {
            case .shutdown:
                self?.doShutdown(error: error)
                self?.cleanupCache()

            case .reconnect:
                self?.doReconnect(error: error)
            }
        }

        // shut down after sending exit notification if socket is unreliable (normally UDP)
        if let link = link, !link.isReliable {
            do {
                guard let packets = try currentKey?.encrypt(packets: [OpenVPN.OCCPacket.exit.serialized()]) else {
                    completion()
                    return
                }
                link.multiplePacketsDataWritten(packets) { [weak self] (_) in
                    self?.queue.sync {
                        completion()
                    }
                }
            } catch {
                completion()
            }
        } else {
            completion()
        }
    }

    private func doShutdown(error: Error?) {
        if let error = error {

        } else {

        }
        stopError = error
        delegate?.sessionDidStop(self, withError: error, shouldReconnect: false)
    }

    private func doReconnect(error: Error?) {
        if let error = error {

        } else {

        }
        stopError = error
        delegate?.sessionDidStop(self, withError: error, shouldReconnect: true)
    }
}
