//
//  OpenVPNTunnelProvider.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 2/1/17.
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

import NetworkExtension

#if os(iOS)
import SystemConfiguration.CaptiveNetwork
#elseif os(macOS)
import CoreWLAN
#endif
import TunnelKitCore
import TunnelKitOpenVPNCore
import TunnelKitManager
import TunnelKitOpenVPNManager
import TunnelKitOpenVPNProtocol
import TunnelKitAppExtension
import CTunnelKitCore
import __TunnelKitUtils



/**
 Provides an all-in-one `NEPacketTunnelProvider` implementation for use in a
 Packet Tunnel Provider extension both on iOS and macOS.
 */
open class OpenVPNTunnelProvider: NEPacketTunnelProvider {

    // MARK: Tweaks

    /// An optional string describing host app version on tunnel start.
    public var appVersion: String?

    /// The log separator between sessions.
    public var logSeparator = "--- EOF ---"

    /// The maximum size of the log.
    public var maxLogSize = 20000

    /// The log level when `OpenVPNTunnelProvider.Configuration.shouldDebug` is enabled.
//    public var debugLogLevel: SwiftyBeaver.Level = .debug

    /// The number of milliseconds after which a DNS resolution fails.
    public var dnsTimeout = 3000

    /// The number of milliseconds after which the tunnel gives up on a connection attempt.
    public var socketTimeout = 5000

    /// The number of milliseconds after which the tunnel is shut down forcibly.
    public var shutdownTimeout = 2000

    /// The number of milliseconds after which a reconnection attempt is issued.
    public var reconnectionDelay = 1000

    /// The number of link failures after which the tunnel is expected to die.
    public var maxLinkFailures = 3

    /// The number of milliseconds between data count updates. Set to 0 to disable updates (default).
    public var dataCountInterval = 0

    /// A list of public DNS servers to use as fallback when none are provided (defaults to CloudFlare).
    public var fallbackDNSServers = [
        "1.1.1.1",
        "1.0.0.1",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001"
    ]

    // MARK: Constants

    private let tunnelQueue = DispatchQueue(label: OpenVPNTunnelProvider.description(), qos: .utility)

    private let prngSeedLength = 64

    private var cachesURL: URL {
        let appGroup = cfg.appGroup
        guard let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) else {
            fatalError("No access to app group: \(appGroup)")
        }
        return containerURL.appendingPathComponent("Library/Caches/")
    }

    // MARK: Tunnel configuration

    private var cfg: OpenVPN.Settings!

    private var strategy: ConnectionStrategy!

    // MARK: Internal state

    private var session: OpenVPNSession?

    private var socket: GalixoSocket?

    private var pendingStartHandler: ((Error?) -> Void)?

    private var pendingStopHandler: (() -> Void)?

    private var isCountingData = false

    private var shouldReconnect = false

    // MARK: NEPacketTunnelProvider (XPC queue)

    open override var reasserting: Bool {
        didSet {

        }
    }

    open override func startTunnel(options: [String: NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {

        // required configuration
        do {
            guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol else {
                throw ConfigurationError.parameter(name: "protocolConfiguration")
            }
            guard let _ = tunnelProtocol.serverAddress else {
                throw ConfigurationError.parameter(name: "protocolConfiguration.serverAddress")
            }
            guard let providerConfiguration = tunnelProtocol.providerConfiguration else {
                throw ConfigurationError.parameter(name: "protocolConfiguration.providerConfiguration")
            }
            cfg = try fromKeyValue(OpenVPN.Settings.self, providerConfiguration)
        } catch let cfgError as ConfigurationError {
            switch cfgError {
            case .parameter(let name):
                NSLog("Tunnel configuration incomplete: \(name)")

            default:
                NSLog("Tunnel configuration error: \(cfgError)")
            }
            completionHandler(cfgError)
            return
        } catch {
            NSLog("Unexpected error in tunnel configuration: \(error)")
            completionHandler(error)
            return
        }

        // prepare for logging (append)
//        configureLogging()

        // logging only ACTIVE from now on




        // override library configuration
        OpenVpnMainConfig.masksPrivateData = cfg.masksPrivateData
        if let versionIdentifier = cfg.versionIdentifier {
            OpenVpnMainConfig.versionIdentifier = versionIdentifier
        }

        // optional credentials
        let credentials: OpenVPN.Credentials?
        if let username = protocolConfiguration.username, let passwordReference = protocolConfiguration.passwordReference {
            guard let password = try? Keychain.password(forReference: passwordReference) else {
                completionHandler(ConfigurationError.credentials(details: "Keychain.password(forReference:)"))
                return
            }
            credentials = OpenVPN.Credentials(username, password)
        } else {
            credentials = nil
        }

        cfg._appexSetLastError(nil)

        guard OpenVPN.prepareRandomNumberGenerator(seedLength: prngSeedLength) else {
            completionHandler(ConfigurationError.prngInitialization)
            return
        }

        if let appVersion = appVersion {

        }
        cfg.print()

        // prepare to pick endpoints
        strategy = ConnectionStrategy(configuration: cfg.configuration)

        let session: OpenVPNSession
        do {
            session = try OpenVPNSession(queue: tunnelQueue, configuration: cfg.configuration, cachesURL: cachesURL)
            refreshDataCount()
        } catch {
            completionHandler(error)
            return
        }
        session.credentials = credentials
        session.delegate = self
        self.session = session

        logCurrentSSID()

        pendingStartHandler = completionHandler
        tunnelQueue.sync {
            self.connectTunnel()
        }
    }

    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        pendingStartHandler = nil

        cfg._appexSetLastError(nil)

        guard let session = session else {
            flushLog()
            completionHandler()
            forceExitOnMac()
            return
        }

        pendingStopHandler = completionHandler
        tunnelQueue.arrange(after: .milliseconds(shutdownTimeout)) { [weak self] in
            guard let weakSelf = self else {
                return
            }
            guard let pendingHandler = weakSelf.pendingStopHandler else {
                return
            }

            weakSelf.flushLog()
            pendingHandler()
            self?.forceExitOnMac()
        }
        tunnelQueue.sync {
            session.shutdown(error: nil)
        }
    }

    // MARK: Wake/Sleep (debugging placeholders)

    open override func wake() {

    }

    open override func sleep(completionHandler: @escaping () -> Void) {

        completionHandler()
    }

    // MARK: Connection (tunnel queue)

    private func connectTunnel(upgradedSocket: GalixoSocket? = nil) {


        // reuse upgraded socket
        if let upgradedSocket = upgradedSocket, !upgradedSocket.off {

            connectTunnel(via: upgradedSocket)
            return
        }

        strategy.createSocket(from: self, timeout: dnsTimeout, queue: tunnelQueue) {
            switch $0 {
            case .success(let socket):
                self.connectTunnel(via: socket)

            case .failure(let error):
                if case .dnsFailure = error {
                    self.tunnelQueue.async {
                        self.strategy.tryNextEndpoint()
                        self.connectTunnel()
                    }
                    return
                }
                self.disposeTunnel(error: error)
            }
        }
    }

    private func connectTunnel(via socket: GalixoSocket) {

        cfg._appexSetLastError(nil)

        self.socket = socket
        self.socket?.delegate = self
        self.socket?.listen(queue: tunnelQueue, activeTimeout: socketTimeout)
    }

    private func finishTunnelDisconnection(error: Error?) {
        if let session = session, !(shouldReconnect && session.canRebindLink()) {
            session.cleanup()
        }

        socket?.delegate = nil
        socket?.stopListening()
        socket = nil

        if let error = error {

            setErrorStatus(with: error)
        } else {

        }
    }

    private func disposeTunnel(error: Error?) {

        tunnelQueue.asyncAfter(deadline: .now() + .milliseconds(reconnectionDelay)) { [weak self] in
            self?.reallyDisposeTunnel(error: error)
        }
    }

    private func reallyDisposeTunnel(error: Error?) {
        flushLog()

        // failed to start
        if pendingStartHandler != nil {

            //
            // CAUTION
            //
            // passing nil to this callback will result in an extremely undesired situation,
            // because NetworkExtension would interpret it as "successfully connected to VPN"
            //
            // if we end up here disposing the tunnel with a pending start handled, we are
            // 100% sure that something wrong happened while starting the tunnel. in such
            // case, here we then must also make sure that an error object is ALWAYS
            // provided, so we do this with optional fallback to .socketActivity
            //
            // socketActivity makes sense, given that any other error would normally come
            // from OpenVPN.stopError. other paths to disposeTunnel() are only coming
            // from stopTunnel(), in which case we don't need to feed an error parameter to
            // the stop completion handler
            //
            pendingStartHandler?(error ?? GalixoTunnelErrors.socketActivity)
            pendingStartHandler = nil
        }
        // stopped intentionally
        else if pendingStopHandler != nil {
            pendingStopHandler?()
            pendingStopHandler = nil
            forceExitOnMac()
        }
        // stopped externally, unrecoverable
        else {
            cancelTunnelWithError(error)
            forceExitOnMac()
        }
    }

    // MARK: Data counter (tunnel queue)

    private func refreshDataCount() {
        guard dataCountInterval > 0 else {
            return
        }
        tunnelQueue.arrange(after: .milliseconds(dataCountInterval)) { [weak self] in
            self?.refreshDataCount()
        }
        guard isCountingData, let session = session, let dataCount = session.dataCount() else {
            cfg._appexSetDataCount(nil)
            return
        }
        cfg._appexSetDataCount(dataCount)
    }
}

extension OpenVPNTunnelProvider: GalixoSocketProtocol {

    // MARK: GenericSocketDelegate (tunnel queue)

    public func socketDidTimeout(_ socket: GalixoSocket) {

        shouldReconnect = true
        socket.shutdown()

        // fallback: TCP connection timeout suggests falling back
        if let _ = socket as? NETCP {
            guard tryNextEndpoint() else {
                // disposeTunnel
                return
            }
        }
    }

    public func socketDidBecomeActive(_ socket: GalixoSocket) {
        guard let session = session, let producer = socket as? URLGeneratorProtocol else {
            return
        }
        if session.canRebindLink() {
            session.rebindLink(producer.link(userObject: cfg.configuration.xorMethod))
            reasserting = false
        } else {
            session.setLink(producer.link(userObject: cfg.configuration.xorMethod))
        }
    }

    public func socket(_ socket: GalixoSocket, didShutdownWithFailure failure: Bool) {
        guard let session = session else {
            return
        }

        var shutdownError: Error?
        let didTimeoutNegotiation: Bool
        var upgradedSocket: GalixoSocket?

        // look for error causing shutdown
        shutdownError = session.stopError
        if failure && (shutdownError == nil) {
            shutdownError = GalixoTunnelErrors.linkError
        }
        if case .negotiationTimeout = shutdownError as? VpnErrors {
            didTimeoutNegotiation = true
        } else {
            didTimeoutNegotiation = false
        }

        // only try upgrade on network errors
        if shutdownError as? VpnErrors == nil {
            upgradedSocket = socket.upgraded()
        }

        // clean up
        finishTunnelDisconnection(error: shutdownError)

        // fallback: UDP is connection-less, treat negotiation timeout as socket timeout
        if didTimeoutNegotiation {
            guard tryNextEndpoint() else {
                // disposeTunnel
                return
            }
        }

        // reconnect?
        if shouldReconnect {

            tunnelQueue.arrange(after: .milliseconds(reconnectionDelay)) {

                // give up if shouldReconnect cleared in the meantime
                guard self.shouldReconnect else {

                    return
                }

                self.reasserting = true
                self.connectTunnel(upgradedSocket: upgradedSocket)
            }
            return
        }

        // shut down
        disposeTunnel(error: shutdownError)
    }

    public func socketHasBetterPath(_ socket: GalixoSocket) {

        logCurrentSSID()
        session?.reconnect(error: GalixoTunnelErrors.networkChanged)
    }
}

extension OpenVPNTunnelProvider: OpenVPNSessionDelegate {

    // MARK: OpenVPNSessionDelegate (tunnel queue)

    public func sessionDidStart(_ session: OpenVPNSession, remoteAddress: String, remoteProtocol: String?, options: OpenVPN.Configuration) {


        if let proto = remoteProtocol {

        }

        cfg.configuration.print(isLocal: true)

        options.print(isLocal: false)

        cfg._appexSetServerConfiguration(session.serverConfiguration() as? OpenVPN.Configuration)

        bringNetworkUp(remoteAddress: remoteAddress, localOptions: session.configuration, remoteOptions: options) { (error) in

            // FIXME: XPC queue

            self.reasserting = false

            if let error = error {

                self.pendingStartHandler?(error)
                self.pendingStartHandler = nil
                return
            }


            session.setTunnel(tunnel: NETCPIMP(nEPacketTunnelFlow: self.packetFlow))

            self.pendingStartHandler?(nil)
            self.pendingStartHandler = nil
        }

        isCountingData = true
        refreshDataCount()
    }

    public func sessionDidStop(_: OpenVPNSession, withError error: Error?, shouldReconnect: Bool) {
        cfg._appexSetServerConfiguration(nil)

        if let error = error {

        } else {

        }

        isCountingData = false
        refreshDataCount()

        self.shouldReconnect = shouldReconnect
        socket?.shutdown()
    }

    private func bringNetworkUp(remoteAddress: String, localOptions: OpenVPN.Configuration, remoteOptions: OpenVPN.Configuration, completionHandler: @escaping (Error?) -> Void) {
        let newSettings = NetworkSettingsBuilder(remoteAddress: remoteAddress, localOptions: localOptions, remoteOptions: remoteOptions)

        guard !newSettings.isGateway || newSettings.hasGateway else {
            session?.shutdown(error: GalixoTunnelErrors.gatewayUnattainable)
            return
        }

//        // block LAN if desired
//        if routingPolicies?.contains(.blockLocal) ?? false {
//            let table = RoutingTable()
//            if isIPv4Gateway,
//                let gateway = table.defaultGateway4()?.gateway(),
//                let route = table.broadestRoute4(matchingDestination: gateway) {
//
//                route.partitioned()?.forEach {
//                    let destination = $0.network()
//                    guard let netmask = $0.networkMask() else {
//                        return
//                    }
//
//                    log.info("Block local: Suppressing IPv4 route \(destination)/\($0.prefix())")
//
//                    let included = NEIPv4Route(destinationAddress: destination, subnetMask: netmask)
//                    included.gatewayAddress = options.ipv4?.defaultGateway
//                    ipv4Settings?.includedRoutes?.append(included)
//                }
//            }
//            if isIPv6Gateway,
//                let gateway = table.defaultGateway6()?.gateway(),
//                let route = table.broadestRoute6(matchingDestination: gateway) {
//
//                route.partitioned()?.forEach {
//                    let destination = $0.network()
//                    let prefix = $0.prefix()
//
//                    log.info("Block local: Suppressing IPv6 route \(destination)/\($0.prefix())")
//
//                    let included = NEIPv6Route(destinationAddress: destination, networkPrefixLength: prefix as NSNumber)
//                    included.gatewayAddress = options.ipv6?.defaultGateway
//                    ipv6Settings?.includedRoutes?.append(included)
//                }
//            }
//        }

        setTunnelNetworkSettings(newSettings.build(), completionHandler: completionHandler)
    }
}

extension OpenVPNTunnelProvider {
    private func tryNextEndpoint() -> Bool {
        guard strategy.tryNextEndpoint() else {
            disposeTunnel(error: GalixoTunnelErrors.exhaustedEndpoints)
            return false
        }
        return true
    }

    // MARK: Logging

//    private func configureLogging() {
//        let logLevel: SwiftyBeaver.Level = (cfg.shouldDebug ? debugLogLevel : .info)
//        let logFormat = cfg.debugLogFormat ?? "$Dyyyy-MM-dd HH:mm:ss.SSS$d $L $N.$F:$l - $M"
//
//        if cfg.shouldDebug {
//            let console = ConsoleDestination()
//            console.useNSLog = true
//            console.minLevel = logLevel
//            console.format = logFormat
//
//        }
//
//        let file = FileDestination(logFileURL: cfg._appexDebugLogURL)
//        file.minLevel = logLevel
//        file.format = logFormat
//        file.logFileMaxSize = maxLogSize
//
//
//        // store path for clients
//        cfg._appexSetDebugLogPath()
//    }

    private func flushLog() {


        // XXX: should enforce SwiftyBeaver flush?
//        if let url = cfg.urlForDebugLog {
//            memoryLog.flush(to: url)
//        }
    }

    private func logCurrentSSID() {
        DeligateListener.getXXID {
            if let ssid = $0 {

            } else {

            }
        }
    }

//    private func anyPointer(_ object: Any?) -> UnsafeMutableRawPointer {
//        let anyObject = object as AnyObject
//        return Unmanaged<AnyObject>.passUnretained(anyObject).toOpaque()
//    }
}

// MARK: Errors

private extension OpenVPNTunnelProvider {
    enum ConfigurationError: Error {

        /// A field in the `OpenVPNProvider.Configuration` provided is incorrect or incomplete.
        case parameter(name: String)

        /// Credentials are missing or inaccessible.
        case credentials(details: String)

        /// The pseudo-random number generator could not be initialized.
        case prngInitialization

        /// The TLS certificate could not be serialized.
        case certificateSerialization
    }

    func setErrorStatus(with error: Error) {
        cfg._appexSetLastError(unifiedError(from: error))
    }

    func unifiedError(from error: Error) -> GalixoTunnelErrors {

        // XXX: error handling is limited by lastError serialization
        // requirement, cannot return a generic Error here
//        openVPNError(from: error) ?? error
        openVPNError(from: error) ?? .linkError
    }

    func openVPNError(from error: Error) -> GalixoTunnelErrors? {
        if let specificError = error.asNativeOpenVPNError ?? error as? VpnErrors {
            switch specificError {
            case .negotiationTimeout, .pingTimeout, .staleSession:
                return .timeout

            case .badCredentials:
                return .authentication

            case .serverCompression:
                return .serverCompression

            case .failedLinkWrite:
                return .linkError

            case .noRouting:
                return .routing

            case .serverShutdown:
                return .serverShutdown

            case .native(let code):
                switch code {
                case .cryptoRandomGenerator, .cryptoAlgorithm:
                    return .encryptionInitialization

                case .cryptoEncryption, .cryptoHMAC:
                    return .encryptionData

                case .tlscaRead, .tlscaUse, .tlscaPeerVerification,
                        .tlsClientCertificateRead, .tlsClientCertificateUse,
                        .tlsClientKeyRead, .tlsClientKeyUse:
                    return .tlsInitialization

                case .tlsServerCertificate, .tlsServerEKU, .tlsServerHost:
                    return .tlsServerVerification

                case .tlsHandshake:
                    return .tlsHandshake

                case .dataPathOverflow, .dataPathPeerIdMismatch:
                    return .unexpectedReply

                case .dataPathCompression:
                    return .serverCompression

                default:
                    break
                }

            default:
                return .unexpectedReply
            }
        }
        return nil
    }
}

// MARK: Hacks

private extension NEPacketTunnelProvider {
    func forceExitOnMac() {
        #if os(macOS)
        exit(0)
        #endif
    }
}
