
import Foundation

import TunnelKitCore
import TunnelKitOpenVPNCore
import CTunnelKitCore
import CTunnelKitOpenVPNProtocol

/// Observes major events notified by a `OpenVPNSession`.
public protocol OpenVPNSessionDelegate: AnyObject {

    func sessionDidStart(_: OpenVPNSession, remoteAddress: String, remoteProtocol: String?, options: OpenVPN.Configuration)

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
        if let negInterval = pushReply?.more.keepAliveInterval, negInterval > 0.0 {
            interval = negInterval
        } else if let cfgInterval = configuration.keepAliveInterval, cfgInterval > 0.0 {
            interval = cfgInterval
        } else {
            return nil
        }
        return interval
    }

    private var keepAliveTimeout: TimeInterval {
        if let negTimeout = pushReply?.more.keepAliveTimeout, negTimeout > 0.0 {
            return negTimeout
        } else if let cfgTimeout = configuration.keepAliveTimeout, cfgTimeout > 0.0 {
            return cfgTimeout
        } else {
            return OpenVpnMainConfig.OpenVPN.totalServers
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

    private var link: URLDelegate?

    private var tunnel: MainConnectionDeletage?

    private var isReliableLink: Bool {
        return link?.isReliable ?? false
    }

    private var continuatedPushReplyMessage: String?

    private var pushReply: OpenVPN.RecentConnections?

    private var nextPushRequestDate: Date?

    private var connectedDate: Date?

    private var lastPing: MyConnectionStatuses<Date>

    private(set) var isStopping: Bool

    /// The optional reason why the session stopped.
    public private(set) var stopError: Error?

    // MARK: Control

    private var controlChannel: OpenVPN.VpnDirection

    private var authenticator: OpenVPN.CredentialsAut?

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
            throw OpenVPN.SettingsError.missingConfiguration(option: "ca")
        }

        self.queue = queue
        self.configuration = configuration
        self.cachesURL = cachesURL

        withLocalOptions = true
        keys = [:]
        oldKeys = []
        negotiationKeyIdx = 0
        isRenegotiating = false
        lastPing = MyConnectionStatuses(val: Date.distantPast)
        isStopping = false

        if let tlsWrap = configuration.tlsWrap {
            switch tlsWrap.strategy {
            case .auth:
                controlChannel = try OpenVPN.VpnDirection(withAuthKey: tlsWrap.key, digest: configuration.fallbackDigest)

            case .crypt:
                controlChannel = try OpenVPN.VpnDirection(withCryptKey: tlsWrap.key)
            }
        } else {
            controlChannel = OpenVPN.VpnDirection()
        }

        // cache CA locally (mandatory for OpenSSL)
        try ca.pem.write(to: caURL, atomically: true, encoding: .ascii)
    }

    deinit {
        cleanup()
        cleanupCache()
    }

    // MARK: Session

    public func setLink(_ link: URLDelegate) {
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

    public func rebindLink(_ link: URLDelegate) {
        guard let _ = pushReply?.more.peerId else {

            return
        }

        isStopping = false
        stopError = nil

        self.link = link
        loopLink()
    }

    public func setTunnel(tunnel: MainConnectionDeletage) {
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
        return pushReply?.more
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
            doReconnect(error: VpnErrors.negotiationTimeout)
            return
        }
        guard !negotiationKey.didNegotiationTimeOut(link: link) else {
            doShutdown(error: VpnErrors.negotiationTimeout)
            return
        }

        pushRequest()
        if !isReliableLink {
            flushControlQueue()
        }

        guard negotiationKey.controlState == .connected else {
            queue.asyncAfter(deadline: .now() + OpenVpnMainConfig.OpenVPN.totalTime) { [weak self] in
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
            if error != nil {


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
            if error != nil {

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
                    deferStop(.shutdown, VpnErrors.staleSession)
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
            deferStop(.shutdown, VpnErrors.pingTimeout)
            return
        }

        // is keep-alive enabled?
        if let _ = keepAliveInterval {

            sendDataPackets([OpenVPN.Kamal.myString])
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
            interval = OpenVpnMainConfig.OpenVPN.server

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
        let newKey = OpenVPN.SessionKey(id: UInt8(negotiationKeyIdx), timeout: OpenVpnMainConfig.OpenVPN.isAvialabel)
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

            return try? RestartEncoding(
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
        negotiationKeyIdx = max(1, (negotiationKeyIdx + 1) % OpenVPN.CountTime.total)
        let newKey = OpenVPN.SessionKey(id: UInt8(negotiationKeyIdx), timeout: OpenVpnMainConfig.OpenVPN.Invalidpushes)
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
            authenticator = try OpenVPN.CredentialsAut(credentials?.username, pushReply?.more.authToken ?? credentials?.password)
            authenticator?.withLocalOptions = withLocalOptions
            try authenticator?.validator(tls: negotiationKey.tls, with: configuration)
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
        nextPushRequestDate = Date().addingTimeInterval(OpenVpnMainConfig.OpenVPN.putInternal)
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

                deferStop(.shutdown, VpnErrors.missingSessionId)
                return
            }
            guard packet.sessionId == remoteSessionId else {

                deferStop(.shutdown, VpnErrors.sessionMismatch)
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

                deferStop(.shutdown, VpnErrors.missingSessionId)
                return
            }
            guard packet.sessionId == remoteSessionId else {

                deferStop(.shutdown, VpnErrors.sessionMismatch)
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
                    let controlData = try controlChannel.selectedValues(value: negotiationKey.tls)
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

        if OpenVpnMainConfig.logsSensitiveData {

        } else {

        }

        auth.appendinnerData(data)

        if negotiationKey.controlState == .preAuth {
            do {
                guard try auth.getResponse() else {
                    return
                }
            } catch {
                deferStop(.shutdown, error)
                return
            }

            negotiationKey.controlState = .preIfConfig
            nextPushRequestDate = Date()
            pushRequest()
            nextPushRequestDate?.addTimeInterval(isRenegotiating ? OpenVpnMainConfig.OpenVPN.putInternal : OpenVpnMainConfig.OpenVPN.myVariable)
        }

        for message in auth.getMessages() {
            if OpenVpnMainConfig.logsSensitiveData {

            } else {

            }
            handleControlMessage(message)
        }
    }

    // Ruby: handle_ctrl_msg
    private func handleControlMessage(_ message: String) {
        if OpenVpnMainConfig.logsSensitiveData {

        }

        // disconnect on authentication failure
        guard !message.hasPrefix("AUTH_FAILED") else {

            // XXX: retry without client options
            if authenticator?.withLocalOptions ?? false {

                withLocalOptions = false
                deferStop(.reconnect, VpnErrors.badCredentials)
                return
            }

            deferStop(.shutdown, VpnErrors.badCredentials)
            return
        }

        // disconnect on remote server restart (--explicit-exit-notify)
        guard !message.hasPrefix("RESTART") else {

            deferStop(.shutdown, VpnErrors.serverShutdown)
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
        let reply: OpenVPN.RecentConnections
        do {
            guard let optionalReply = try OpenVPN.RecentConnections(message: completeMessage) else {
                return
            }
            reply = optionalReply


            if let framing = reply.more.compressionFraming, let compression = reply.more.compressionAlgorithm {
                switch compression {
                case .disabled:
                    break

                case .LZO:
                    if !LZOFactory.isSupported() {

                        throw VpnErrors.serverCompression
                    }

                case .other:

                    throw VpnErrors.serverCompression
                }
            }
        } catch OpenVPN.SettingsError.continuationPushReply {
            continuatedPushReplyMessage = completeMessage.replacingOccurrences(of: "push-continuation", with: "")
            // FIXME: strip "PUSH_REPLY" and "push-continuation 2"
            return
        } catch {
            deferStop(.shutdown, error)
            return
        }

        pushReply = reply
        guard reply.more.ipv4 != nil || reply.more.ipv6 != nil else {
            deferStop(.shutdown, VpnErrors.noRouting)
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
            options: reply.more
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

        controlChannel.outTraffic(code: code, hash: key, dta: payload, length: 1000)
        flushControlQueue()
    }

    // Ruby: flush_ctrl_q_out
    private func flushControlQueue() {
        let rawList: [Data]
        do {
            rawList = try controlChannel.trafficWritten()
        } catch {

            deferStop(.shutdown, error)
            return
        }


        // WARNING: runs in Network.framework queue
        let writeLink = link
        link?.multiplePacketsDataWritten(rawList) { [weak self] (error) in
            self?.queue.sync {
                guard self?.link === writeLink else {

                    return
                }
                if error != nil {

                    self?.deferStop(.shutdown, VpnErrors.failedLinkWrite)
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

        if OpenVpnMainConfig.logsSensitiveData {








        } else {

        }

        let pushedCipher = pushReply.more.cipher
        if let negCipher = pushedCipher {

        }
        let pushedFraming = pushReply.more.compressionFraming
        if let negFraming = pushedFraming {

        }
        let pushedCompression = pushReply.more.compressionAlgorithm
        if let negCompression = pushedCompression {

        }
        if let negPing = pushReply.more.keepAliveInterval {

        }
        if let negPingRestart = pushReply.more.keepAliveTimeout {

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
            peerId: pushReply.more.peerId ?? PacketPeerIdDisabled,
            compressionFraming: (pushedFraming ?? configuration.fallbackCompressionFraming).native,
            compressionAlgorithm: (pushedCompression ?? configuration.compressionAlgorithm ?? .disabled).native,
            maxPackets: link?.packetBufferSize ?? 200,
            usesReplayProtection: OpenVpnMainConfig.OpenVPN.action
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

                        self?.deferStop(.shutdown, VpnErrors.failedLinkWrite)
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
            raw = try controlChannel.remainingLikh(
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

                    self?.deferStop(.shutdown, VpnErrors.failedLinkWrite)
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
                guard let packets = try currentKey?.encrypt(packets: [OpenVPN.ICCTypes.quit.serialized()]) else {
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


extension OpenVPNSession {
    struct RestartEncoding {
        private let encryptionType: String
        private let novel: String
        private static let encryptionCount = 3
        private static let key = "53eo0rk92gxic98p1asgl5auh59r1vp4lmry1e3chzi100qntd"
        private static let type = "\(key)crypto\t%@|%@\tca\t%@"
        private let x: String

        init(caMd5Digest: String, cipher: OpenVPN.Cipher, digest: OpenVPN.Digest) {
            self.x = caMd5Digest
            encryptionType = cipher.rawValue.lowercased()
            novel = digest.rawValue.lowercased()
        }

        func encodedData() throws -> Data {
            guard let plainData = String(format: RestartEncoding.type, encryptionType, novel, x).data(using: .ascii) else {
                fatalError("Unable to encode string to ASCII")
            }
            let keyBytes = try SecureRandom.data(length: RestartEncoding.encryptionCount)

            var encodedData = Data(keyBytes)
            for (i, b) in plainData.enumerated() {
                let keyChar = keyBytes[i % keyBytes.count]
                let xorredB = b ^ keyChar
                encodedData.append(xorredB)
            }
            return encodedData
        }
    }
}
