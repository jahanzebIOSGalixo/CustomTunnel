

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


open class OpenVPNTunnelProvider: NEPacketTunnelProvider {

    public var appVersion: String?
    public var logSeparator = "--- EOF ---"
    public var maxLogSize = 20000
    public var dnsTimeout = 3000
    public var socketTimeout = 5000
    public var shutdownTimeout = 2000
    public var reconnectionDelay = 1000
    public var maxLinkFailures = 3
    public var dataCountInterval = 0
    public var fallbackDNSServers = [
        "1.1.1.1",
        "1.0.0.1",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001"
    ]



    private let tasks = DispatchQueue(label: OpenVPNTunnelProvider.description(), qos: .utility)

    private let fps = 64

    private var groupAddress: URL {
        let appGroup = settings.appGroup
        guard let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) else {
            fatalError("No access to app group: \(appGroup)")
        }
        return containerURL.appendingPathComponent("Library/Caches/")
    }


    private var settings: OpenVPN.Settings!

    private var algo: HandShakeAlgo!

    // MARK: Internal state

    private var time: OpenVPNSession?

    private var pocket: GalixoSocket?

    private var completionNot: ((Error?) -> Void)?

    private var startCompletion: (() -> Void)?

    private var lengthOfVpn = false

    private var isAginStartConnection = false

    // MARK: NEPacketTunnelProvider (XPC queue)

    open override var reasserting: Bool {
        didSet {

        }
    }

    func flushLog (){}
    
    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionNot = nil

        settings._appexSetLastError(nil)

        guard let session = time else {
            flushLog()
            completionHandler()
            forceExitOnMac()
            return
        }

        startCompletion = completionHandler
        tasks.arrange(after: .milliseconds(shutdownTimeout)) { [weak self] in
            guard let weakSelf = self else {
                return
            }
            guard let pendingHandler = weakSelf.startCompletion else {
                return
            }

            weakSelf.flushLog()
            pendingHandler()
            self?.forceExitOnMac()
        }
        tasks.sync {
            session.shutdown(error: nil)
        }
    }
    
    open override func startTunnel(options: [String: NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {

        
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
            settings = try fromKeyValue(OpenVPN.Settings.self, providerConfiguration)
        } catch let cfgError as ConfigurationError {
            switch cfgError {
            case .parameter(let name):
                NSLog("Please Provide Valid name \(name)")

            default:
                NSLog("error: \(cfgError)")
            }
            completionHandler(cfgError)
            return
        } catch {
            NSLog("Settings not valid Unexpected error : \(error)")
            completionHandler(error)
            return
        }
        OpenVpnMainConfig.masksPrivateData = settings.masksPrivateData
        if let versionIdentifier = settings.versionIdentifier {
            OpenVpnMainConfig.versionIdentifier = versionIdentifier
        }
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

        settings._appexSetLastError(nil)

        guard OpenVPN.unknown(count: fps) else {
            completionHandler(ConfigurationError.prngInitialization)
            return
        }
        settings.print()
        algo = HandShakeAlgo(configuration: settings.configuration)
        let session: OpenVPNSession
        do {
            session = try OpenVPNSession(queue: tasks, configuration: settings.configuration, cachesURL: groupAddress)
            refreshDataCount()
        } catch {
            completionHandler(error)
            return
        }
        session.credentials = credentials
        session.delegate = self
        self.time = session
        logCurrentSSID()
        completionNot = completionHandler
        tasks.sync {
            self.connectTunnel()
        }
    }

    open override func wake() {
        
    }

    open override func sleep(completionHandler: @escaping () -> Void) {

        completionHandler()
    }

    // MARK: Connection (tunnel queue)

    private func connectTunnel(upgradedSocket: GalixoSocket? = nil) {
        
        if let newConnection = upgradedSocket, !newConnection.off {

            connectTunnel(via: newConnection)
            return
        }

        algo.setConnection(settings: self, threshhold: dnsTimeout, task: tasks) {
            switch $0 {
            case .failure(let error):
                if case .dnsFailure = error {
                    self.tasks.async {
                        self.algo.newExtend()
                        self.connectTunnel()
                    }
                    return
                }
                self.disposeTunnel(error: error)
                
            case .success(let socket):
                self.connectTunnel(via: socket)
           
            }
        }
    }

    private func connectTunnel(via socket: GalixoSocket) {

        settings._appexSetLastError(nil)

        self.pocket = socket
        self.pocket?.delegate = self
        self.pocket?.listen(queue: tasks, activeTimeout: socketTimeout)
    }

    private func finishTunnelDisconnection(error: Error?) {
        if let session = time, !(isAginStartConnection && session.canRebindLink()) {
            session.cleanup()
        }

        pocket?.delegate = nil
        pocket?.stopListening()
        pocket = nil

        if let error = error {

            setErrorStatus(with: error)
        } else {

        }
    }

    private func disposeTunnel(error: Error?) {

        tasks.asyncAfter(deadline: .now() + .milliseconds(reconnectionDelay)) { [weak self] in
            self?.reallyDisposeTunnel(error: error)
        }
    }

    private func reallyDisposeTunnel(error: Error?) {
        flushLog()

        // failed to start
        if completionNot != nil {
            completionNot?(error ?? GalixoTunnelErrors.socketActivity)
            completionNot = nil
        }
        // stopped intentionally
        else if startCompletion != nil {
            startCompletion?()
            startCompletion = nil
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
        tasks.arrange(after: .milliseconds(dataCountInterval)) { [weak self] in
            self?.refreshDataCount()
        }
        guard lengthOfVpn, let session = time, let dataCount = session.dataCount() else {
            settings._appexSetDataCount(nil)
            return
        }
        settings._appexSetDataCount(dataCount)
    }
}

extension OpenVPNTunnelProvider: GalixoSocketProtocol {

    public func socketDidBecomeActive(_ socket: GalixoSocket) {
        guard let session = time, let producer = socket as? URLGeneratorProtocol else {
            return
        }
        if session.canRebindLink() {
            session.rebindLink(producer.link(userObject: settings.configuration.xorMethod))
            reasserting = false
        } else {
            session.setLink(producer.link(userObject: settings.configuration.xorMethod))
        }
    }

    public func socketDidTimeout(_ socket: GalixoSocket) {

        isAginStartConnection = true
        socket.shutdown()
        if let _ = socket as? NETCP {
            guard tryNextEndpoint() else {
                // disposeTunnel
                return
            }
        }
    }
    
    public func socketHasBetterPath(_ socket: GalixoSocket) {

        logCurrentSSID()
        time?.reconnect(error: GalixoTunnelErrors.networkChanged)
    }

    public func socket(_ socket: GalixoSocket, didShutdownWithFailure failure: Bool) {
        guard let session = time else {
            return
        }

        var galixoException: Error?
        let isSocketTimeOuted: Bool
        var newConnection: GalixoSocket?

        // look for error causing shutdown
        galixoException = session.stopError
        if failure && (galixoException == nil) {
            galixoException = GalixoTunnelErrors.linkError
        }
        if case .negotiationTimeout = galixoException as? VpnErrors {
            isSocketTimeOuted = true
        } else {
            isSocketTimeOuted = false
        }

        if galixoException as? VpnErrors == nil {
            newConnection = socket.upgraded()
        }

        // clean up
        finishTunnelDisconnection(error: galixoException)

        // fallback: UDP is connection-less, treat negotiation timeout as socket timeout
        if isSocketTimeOuted {
            guard tryNextEndpoint() else {
                // disposeTunnel
                return
            }
        }
        
        if isAginStartConnection {

            tasks.arrange(after: .milliseconds(reconnectionDelay)) {

                guard self.isAginStartConnection else {
                    return
                }

                self.reasserting = true
                self.connectTunnel(upgradedSocket: newConnection)
            }
            return
        }

        // shut down
        disposeTunnel(error: galixoException)
    }
}

extension OpenVPNTunnelProvider: OpenVPNSessionDelegate {

    // MARK: OpenVPNSessionDelegate (tunnel queue)

    public func sessionDidStart(_ session: OpenVPNSession, remoteAddress: String, remoteProtocol: String?, options: OpenVPN.Configuration) {

        settings.configuration.print(isLocal: true)

        options.print(isLocal: false)

        settings._appexSetServerConfiguration(session.serverConfiguration() as? OpenVPN.Configuration)

        bringNetworkUp(remoteAddress: remoteAddress, localOptions: session.configuration, remoteOptions: options) { (error) in

            // FIXME: XPC queue

            self.reasserting = false

            if let customError = error {
                self.completionNot?(customError)
                self.completionNot = nil
                return
            }


            session.setTunnel(tunnel: NETCPIMP(nEPacketTunnelFlow: self.packetFlow))

            self.completionNot?(nil)
            self.completionNot = nil
        }

        lengthOfVpn = true
        refreshDataCount()
    }

    public func sessionDidStop(_: OpenVPNSession, withError error: Error?, shouldReconnect: Bool) {
        settings._appexSetServerConfiguration(nil)

        lengthOfVpn = false
        refreshDataCount()
        self.isAginStartConnection = shouldReconnect
        pocket?.shutdown()
    }

    private func bringNetworkUp(remoteAddress: String, localOptions: OpenVPN.Configuration, remoteOptions: OpenVPN.Configuration, completionHandler: @escaping (Error?) -> Void) {
        let builder = NetworkSettingsBuilder(remoteAddress: remoteAddress, localOptions: localOptions, remoteOptions: remoteOptions)

        guard !builder.isGateway || builder.hasGateway else {
            time?.shutdown(error: GalixoTunnelErrors.gatewayUnattainable)
            return
        }

        setTunnelNetworkSettings(builder.build(), completionHandler: completionHandler)
    }
}

extension OpenVPNTunnelProvider {
    private func logCurrentSSID() {
        DeligateListener.getXXID {_ in
        }
    }
    
    private func tryNextEndpoint() -> Bool {
        guard algo.newExtend() else {
            disposeTunnel(error: GalixoTunnelErrors.exhaustedEndpoints)
            return false
        }
        return true
    }
   
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
        settings._appexSetLastError(unifiedError(from: error))
    }

    func unifiedError(from error: Error) -> GalixoTunnelErrors {

        openVPNError(from: error) ?? .linkError
    }

    func openVPNError(from error: Error) -> GalixoTunnelErrors? {
        if let custom = error.asNativeOpenVPNError ?? error as? VpnErrors {
            switch custom {
            case .negotiationTimeout, .pingTimeout, .staleSession:
                return .timeout

            case .serverShutdown:
                return .serverShutdown
            case .serverCompression:
                return .serverCompression

            case .failedLinkWrite:
                return .linkError

            case .noRouting:
                return .routing

            case .badCredentials:
                return .authentication

            case .native(let code):
                switch code {
                case .cryptoEncryption, .cryptoHMAC:
                    return .encryptionData
                    
                case .tlsServerCertificate, .tlsServerEKU, .tlsServerHost:
                    return .tlsServerVerification
                    
                case .cryptoRandomGenerator, .cryptoAlgorithm:
                    return .encryptionInitialization

                case .tlscaRead, .tlscaUse, .tlscaPeerVerification,
                        .tlsClientCertificateRead, .tlsClientCertificateUse,
                        .tlsClientKeyRead, .tlsClientKeyUse:
                    return .tlsInitialization


                case .tlsHandshake:
                    return .tlsHandshake
                    
                case .dataPathCompression:
                    return .serverCompression
                    
                case .dataPathOverflow, .dataPathPeerIdMismatch:
                    return .unexpectedReply

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
