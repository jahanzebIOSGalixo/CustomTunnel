//
//  ConfigurationParser.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 9/5/18.
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

import Foundation

import TunnelKitCore
import CTunnelKitCore
import __TunnelKitUtils



extension OpenVPN {

    /// Provides methods to parse a `Configuration` from an .ovpn configuration file.
    public class ConfigurationParser {

        // XXX: parsing is very optimistic

        /// Regexes used to parse OpenVPN options.
        public struct Regex {

            // MARK: General

            static let cipher = NSRegularExpression("^cipher +[^,\\s]+")

            static let dataCiphers = NSRegularExpression("^(data-ciphers|ncp-ciphers) +[^,\\s]+(:[^,\\s]+)*")

            static let dataCiphersFallback = NSRegularExpression("^data-ciphers-fallback +[^,\\s]+")

            static let auth = NSRegularExpression("^auth +[\\w\\-]+")

            static let compLZO = NSRegularExpression("^comp-lzo.*")

            static let compress = NSRegularExpression("^compress.*")

            static let keyDirection = NSRegularExpression("^key-direction +\\d")

            static let ping = NSRegularExpression("^ping +\\d+")

            static let pingRestart = NSRegularExpression("^ping-restart +\\d+")

            static let keepAlive = NSRegularExpression("^keepalive +\\d+ ++\\d+")

            static let renegSec = NSRegularExpression("^reneg-sec +\\d+")

            static let blockBegin = NSRegularExpression("^<[\\w\\-]+>")

            static let blockEnd = NSRegularExpression("^<\\/[\\w\\-]+>")

            // MARK: Client

            static let proto = NSRegularExpression("^proto +(udp[46]?|tcp[46]?)")

            static let port = NSRegularExpression("^port +\\d+")

            static let remote = NSRegularExpression("^remote +[^ ]+( +\\d+)?( +(udp[46]?|tcp[46]?))?")

            static let authUserPass = NSRegularExpression("^auth-user-pass")

            static let eku = NSRegularExpression("^remote-cert-tls +server")

            static let remoteRandom = NSRegularExpression("^remote-random")

            static let remoteRandomHostname = NSRegularExpression("^remote-random-hostname")

            static let mtu = NSRegularExpression("^tun-mtu +\\d+")

            // MARK: Server

            public static let authToken = NSRegularExpression("^auth-token +[a-zA-Z0-9/=+]+")

            static let peerId = NSRegularExpression("^peer-id +[0-9]+")

            // MARK: Routing

            static let topology = NSRegularExpression("^topology +(net30|p2p|subnet)")

            static let ifconfig = NSRegularExpression("^ifconfig +[\\d\\.]+ [\\d\\.]+")

            static let ifconfig6 = NSRegularExpression("^ifconfig-ipv6 +[\\da-fA-F:]+/\\d+ [\\da-fA-F:]+")

            static let route = NSRegularExpression("^route +[\\d\\.]+( +[\\d\\.]+){0,2}")

            static let route6 = NSRegularExpression("^route-ipv6 +[\\da-fA-F:]+/\\d+( +[\\da-fA-F:]+){0,2}")

            static let gateway = NSRegularExpression("^route-gateway +[\\d\\.]+")

            static let dns = NSRegularExpression("^dhcp-option +DNS6? +[\\d\\.a-fA-F:]+")

            static let domain = NSRegularExpression("^dhcp-option +DOMAIN +[^ ]+")

            static let domainSearch = NSRegularExpression("^dhcp-option +DOMAIN-SEARCH +[^ ]+")

            static let proxy = NSRegularExpression("^dhcp-option +PROXY_(HTTPS? +[^ ]+ +\\d+|AUTO_CONFIG_URL +[^ ]+)")

            static let proxyBypass = NSRegularExpression("^dhcp-option +PROXY_BYPASS +.+")

            static let redirectGateway = NSRegularExpression("^redirect-gateway.*")

            static let routeNoPull = NSRegularExpression("^route-nopull")

            // MARK: Extra

            static let xorInfo = NSRegularExpression("^scramble +(xormask|xorptrpos|reverse|obfuscate)[\\s]?([^\\s]+)?")

            // MARK: Unsupported

//            static let fragment = NSRegularExpression("^fragment +\\d+")
            static let fragment = NSRegularExpression("^fragment")

            static let connectionProxy = NSRegularExpression("^\\w+-proxy")

            static let externalFiles = NSRegularExpression("^(ca|cert|key|tls-auth|tls-crypt) ")

            static let connection = NSRegularExpression("^<connection>")

            // MARK: Continuation

            static let continuation = NSRegularExpression("^push-continuation [12]")
        }

        private enum Topology: String {
            case net30

            case p2p

            case subnet
        }

        private enum RedirectGateway: String {
            case def1 // default

            case noIPv4 = "!ipv4"

            case ipv6

            case local

            case autolocal

            case blockLocal = "block-local"

            case bypassDHCP = "bypass-dhcp"

            case bypassDNS = "bypass-dns"
        }

        /// Result of the parser.
        public struct Result {

            /// Original URL of the configuration file, if parsed from an URL.
            public let url: URL?

            /// The overall parsed `Configuration`.
            public let configuration: Configuration

            /// The lines of the configuration file stripped of any sensitive data. Lines that
            /// the parser does not recognize are discarded in the first place.
            ///
            /// - Seealso: `ConfigurationParser.parsed(...)`
            public let strippedLines: [String]?

            /// Holds an optional `ConfigurationError` that didn't block the parser, but it would be worth taking care of.
            public let warning: SettingsError?
        }

        /**
         Parses a configuration from a .ovpn file.
         
         - Parameter url: The URL of the configuration file.
         - Parameter passphrase: The optional passphrase for encrypted data.
         - Parameter returnsStripped: When `true`, stores the stripped file into `Result.strippedLines`. Defaults to `false`.
         - Returns: The `Result` outcome of the parsing.
         - Throws: `ConfigurationError` if the configuration file is wrong or incomplete.
         */
        public static func parsed(fromURL url: URL, passphrase: String? = nil, returnsStripped: Bool = false) throws -> Result {
            let contents = try String(contentsOf: url)
            return try parsed(
                fromContents: contents,
                passphrase: passphrase,
                originalURL: url,
                returnsStripped: returnsStripped
            )
        }

        /**
         Parses a configuration from a string.
         
         - Parameter contents: The contents of the configuration file.
         - Parameter passphrase: The optional passphrase for encrypted data.
         - Parameter originalURL: The optional original URL of the configuration file.
         - Parameter returnsStripped: When `true`, stores the stripped file into `Result.strippedLines`. Defaults to `false`.
         - Returns: The `Result` outcome of the parsing.
         - Throws: `ConfigurationError` if the configuration file is wrong or incomplete.
         */
        public static func parsed(
            fromContents contents: String,
            passphrase: String? = nil,
            originalURL: URL? = nil,
            returnsStripped: Bool = false
        ) throws -> Result {
            let lines = contents.trimmedLines()
            return try parsed(
                fromLines: lines,
                isClient: true,
                passphrase: passphrase,
                originalURL: originalURL,
                returnsStripped: returnsStripped
            )
        }

        /**
         Parses a configuration from an array of lines.
         
         - Parameter lines: The array of lines holding the configuration.
         - Parameter isClient: Enables additional checks for client configurations.
         - Parameter passphrase: The optional passphrase for encrypted data.
         - Parameter originalURL: The optional original URL of the configuration file.
         - Parameter returnsStripped: When `true`, stores the stripped file into `Result.strippedLines`. Defaults to `false`.
         - Returns: The `Result` outcome of the parsing.
         - Throws: `ConfigurationError` if the configuration file is wrong or incomplete.
         */
        public static func parsed(
            fromLines lines: [String],
            isClient: Bool = false,
            passphrase: String? = nil,
            originalURL: URL? = nil,
            returnsStripped: Bool = false
        ) throws -> Result {
            var optStrippedLines: [String]? = returnsStripped ? [] : nil
            var optWarning: SettingsError?
            var unsupportedError: SettingsError?
            var currentBlockName: String?
            var currentBlock: [String] = []

            var optDataCiphers: [Cipher]?
            var optDataCiphersFallback: Cipher?
            var optCipher: Cipher?
            var optDigest: Digest?
            var optCompressionFraming: ResizingBounds?
            var optCompressionAlgorithm: Resizing?
            var optCA: Encryptor?
            var optClientCertificate: Encryptor?
            var optClientKey: Encryptor?
            var optKeyDirection: FixedCreds.Direction?
            var optTLSKeyLines: [Substring]?
            var optTLSStrategy: TLSWrap.Strategy?
            var optKeepAliveSeconds: TimeInterval?
            var optKeepAliveTimeoutSeconds: TimeInterval?
            var optRenegotiateAfterSeconds: TimeInterval?
            //
            var optDefaultProto: TotalServerCount?
            var optDefaultPort: UInt16?
            var optRemotes: [(String, UInt16?, TotalServerCount?)] = [] // address, port, socket
            var authUserPass = false
            var optChecksEKU: Bool?
            var optRandomizeEndpoint: Bool?
            var optRandomizeHostnames: Bool?
            var optMTU: Int?
            //
            var optAuthToken: String?
            var optPeerId: UInt32?
            //
            var optTopology: String?
            var optIfconfig4Arguments: [String]?
            var optIfconfig6Arguments: [String]?
            var optGateway4Arguments: [String]?
            var optRoutes4: [(String, String, String?)]?    // address, netmask, gateway
            var optRoutes6: [(String, UInt8, String?)]?     // destination, prefix, gateway
            var optDNSServers: [String]?
            var optDomain: String?
            var optSearchDomains: [String]?
            var optHTTPProxy: GalixoServer?
            var optHTTPSProxy: GalixoServer?
            var optProxyAutoConfigurationURL: URL?
            var optProxyBypass: [String]?
            var optRedirectGateway: Set<RedirectGateway>?
            var optRouteNoPull: Bool?
            //
            var optXorMethod: XORMethod?

            for line in lines {


                var isHandled = false
                var strippedLine = line
                defer {
                    if isHandled {
                        optStrippedLines?.append(strippedLine)
                    }
                }

                // MARK: Unsupported

                // check blocks first
                Regex.connection.galixoComponents(in: line) { (_) in
                    unsupportedError = SettingsError.unsupportedConfiguration(option: "<connection> blocks")
                }
                Regex.fragment.galixoComponents(in: line) { (_) in
                    unsupportedError = SettingsError.unsupportedConfiguration(option: "fragment")
                }
                Regex.connectionProxy.galixoComponents(in: line) { (_) in
                    unsupportedError = SettingsError.unsupportedConfiguration(option: "proxy: \"\(line)\"")
                }
                Regex.externalFiles.galixoComponents(in: line) { (_) in
                    unsupportedError = SettingsError.unsupportedConfiguration(option: "external file: \"\(line)\"")
                }
                if line.contains("mtu") || line.contains("mssfix") {
                    isHandled = true
                }

                // MARK: Continuation

                var isContinuation = false
                Regex.continuation.galixoArguments(in: line) {
                    isContinuation = ($0.first == "2")
                }
                guard !isContinuation else {
                    throw SettingsError.continuationPushReply
                }

                // MARK: Inline content

                if unsupportedError == nil {
                    if currentBlockName == nil {
                        Regex.blockBegin.galixoComponents(in: line) {
                            isHandled = true
                            let tag = $0.first!
                            let from = tag.index(after: tag.startIndex)
                            let to = tag.index(before: tag.endIndex)

                            currentBlockName = String(tag[from..<to])
                            currentBlock = []
                        }
                    }
                    Regex.blockEnd.galixoComponents(in: line) {
                        isHandled = true
                        let tag = $0.first!
                        let from = tag.index(tag.startIndex, offsetBy: 2)
                        let to = tag.index(before: tag.endIndex)

                        let blockName = String(tag[from..<to])
                        guard blockName == currentBlockName else {
                            return
                        }

                        // first is opening tag
                        currentBlock.removeFirst()
                        switch blockName {
                        case "ca":
                            optCA = Encryptor(pem: currentBlock.joined(separator: "\n"))

                        case "cert":
                            optClientCertificate = Encryptor(pem: currentBlock.joined(separator: "\n"))

                        case "key":
                            ConfigurationParser.normalizeEncryptedPEMBlock(block: &currentBlock)
                            optClientKey = Encryptor(pem: currentBlock.joined(separator: "\n"))

                        case "tls-auth":
                            optTLSKeyLines = currentBlock.map(Substring.init(_:))
                            optTLSStrategy = .auth

                        case "tls-crypt":
                            optTLSKeyLines = currentBlock.map(Substring.init(_:))
                            optTLSStrategy = .crypt

                        default:
                            break
                        }
                        currentBlockName = nil
                        currentBlock = []
                    }
                }
                if let _ = currentBlockName {
                    currentBlock.append(line)
                    continue
                }

                // MARK: General

                Regex.cipher.galixoArguments(in: line) {
                    isHandled = true
                    guard let rawValue = $0.first else {
                        return
                    }
                    optCipher = Cipher(rawValue: rawValue.uppercased())
                }
                Regex.dataCiphers.galixoArguments(in: line) {
                    isHandled = true
                    guard let rawValue = $0.first else {
                        return
                    }
                    let rawCiphers = rawValue.components(separatedBy: ":")
                    optDataCiphers = []
                    rawCiphers.forEach {
                        guard let cipher = Cipher(rawValue: $0.uppercased()) else {
                            return
                        }
                        optDataCiphers?.append(cipher)
                    }
                }
                Regex.dataCiphersFallback.galixoArguments(in: line) {
                    isHandled = true
                    guard let rawValue = $0.first else {
                        return
                    }
                    optDataCiphersFallback = Cipher(rawValue: rawValue.uppercased())
                }
                Regex.auth.galixoArguments(in: line) {
                    isHandled = true
                    guard let rawValue = $0.first else {
                        return
                    }
                    optDigest = Digest(rawValue: rawValue.uppercased())
                    if optDigest == nil {
                        unsupportedError = SettingsError.unsupportedConfiguration(option: "auth \(rawValue)")
                    }
                }
                Regex.compLZO.galixoArguments(in: line) {
                    isHandled = true
                    optCompressionFraming = .compLZO

                    if !LZOFactory.isSupported() {
                        guard let arg = $0.first else {
                            optWarning = optWarning ?? .unsupportedConfiguration(option: line)
                            return
                        }
                        guard arg == "no" else {
                            unsupportedError = .unsupportedConfiguration(option: line)
                            return
                        }
                    } else {
                        let arg = $0.first
                        optCompressionAlgorithm = (arg == "no") ? .disabled : .LZO
                    }
                }
                Regex.compress.galixoArguments(in: line) {
                    isHandled = true
                    optCompressionFraming = .compress

                    if !LZOFactory.isSupported() {
                        guard $0.isEmpty else {
                            unsupportedError = .unsupportedConfiguration(option: line)
                            return
                        }
                    } else {
                        if let arg = $0.first {
                            switch arg {
                            case "lzo":
                                optCompressionAlgorithm = .LZO

                            case "stub":
                                optCompressionAlgorithm = .disabled

                            case "stub-v2":
                                optCompressionFraming = .compressV2
                                optCompressionAlgorithm = .disabled

                            default:
                                optCompressionAlgorithm = .other
                            }
                        } else {
                            optCompressionAlgorithm = .disabled
                        }
                    }
                }
                Regex.keyDirection.galixoArguments(in: line) {
                    isHandled = true
                    guard let arg = $0.first, let value = Int(arg) else {
                        return
                    }
                    optKeyDirection = FixedCreds.Direction(rawValue: value)
                }
                Regex.ping.galixoArguments(in: line) {
                    isHandled = true
                    guard let arg = $0.first else {
                        return
                    }
                    optKeepAliveSeconds = TimeInterval(arg)
                }
                Regex.pingRestart.galixoArguments(in: line) {
                    isHandled = true
                    guard let arg = $0.first else {
                        return
                    }
                    optKeepAliveTimeoutSeconds = TimeInterval(arg)
                }
                Regex.keepAlive.galixoArguments(in: line) {
                    isHandled = true
                    guard let ping = $0.first, let pingRestart = $0.last else {
                        return
                    }
                    optKeepAliveSeconds = TimeInterval(ping)
                    optKeepAliveTimeoutSeconds = TimeInterval(pingRestart)
                }
                Regex.renegSec.galixoArguments(in: line) {
                    isHandled = true
                    guard let arg = $0.first else {
                        return
                    }
                    optRenegotiateAfterSeconds = TimeInterval(arg)
                }

                // MARK: Client

                Regex.proto.galixoArguments(in: line) {
                    isHandled = true
                    guard let str = $0.first else {
                        return
                    }
                    optDefaultProto = TotalServerCount(protoString: str)
                    if optDefaultProto == nil {
                        unsupportedError = SettingsError.unsupportedConfiguration(option: "proto \(str)")
                    }
                }
                Regex.port.galixoArguments(in: line) {
                    isHandled = true
                    guard let str = $0.first else {
                        return
                    }
                    optDefaultPort = UInt16(str)
                }
                Regex.remote.galixoArguments(in: line) {
                    isHandled = true
                    guard let hostname = $0.first else {
                        return
                    }
                    var port: UInt16?
                    var proto: TotalServerCount?
                    var strippedComponents = ["remote", "<hostname>"]
                    if $0.count > 1 {
                        port = UInt16($0[1])
                        strippedComponents.append($0[1])
                    }
                    if $0.count > 2 {
                        proto = TotalServerCount(protoString: $0[2])
                        strippedComponents.append($0[2])
                    }
                    optRemotes.append((hostname, port, proto))

                    // replace private data
                    strippedLine = strippedComponents.joined(separator: " ")
                }
                Regex.eku.galixoComponents(in: line) { (_) in
                    isHandled = true
                    optChecksEKU = true
                }
                Regex.remoteRandom.galixoComponents(in: line) { (_) in
                    isHandled = true
                    optRandomizeEndpoint = true
                }
                Regex.remoteRandomHostname.galixoComponents(in: line) { _ in
                    isHandled = true
                    optRandomizeHostnames = true
                }
                Regex.mtu.galixoArguments(in: line) {
                    isHandled = true
                    guard let str = $0.first else {
                        return
                    }
                    optMTU = Int(str)
                }
                Regex.authUserPass.galixoComponents(in: line) { _ in
                    isHandled = true
                    authUserPass = true
                }

                // MARK: Server

                Regex.authToken.galixoArguments(in: line) {
                    optAuthToken = $0[0]
                }
                Regex.peerId.galixoArguments(in: line) {
                    optPeerId = UInt32($0[0])
                }

                // MARK: Routing

                Regex.topology.galixoArguments(in: line) {
                    optTopology = $0.first
                }
                Regex.ifconfig.galixoArguments(in: line) {
                    optIfconfig4Arguments = $0
                }
                Regex.ifconfig6.galixoArguments(in: line) {
                    optIfconfig6Arguments = $0
                }
                Regex.route.galixoArguments(in: line) {
                    let routeEntryArguments = $0

                    let address = routeEntryArguments[0]
                    let mask = (routeEntryArguments.count > 1) ? routeEntryArguments[1] : "255.255.255.255"
                    var gateway = (routeEntryArguments.count > 2) ? routeEntryArguments[2] : nil // defaultGateway4
                    if gateway == "vpn_gateway" {
                        gateway = nil
                    }
                    if optRoutes4 == nil {
                        optRoutes4 = []
                    }
                    optRoutes4?.append((address, mask, gateway))
                }
                Regex.route6.galixoArguments(in: line) {
                    let routeEntryArguments = $0

                    let destinationComponents = routeEntryArguments[0].components(separatedBy: "/")
                    guard destinationComponents.count == 2 else {
                        return
                    }
                    guard let prefix = UInt8(destinationComponents[1]) else {
                        return
                    }

                    let destination = destinationComponents[0]
                    var gateway = (routeEntryArguments.count > 1) ? routeEntryArguments[1] : nil // defaultGateway6
                    if gateway == "vpn_gateway" {
                        gateway = nil
                    }
                    if optRoutes6 == nil {
                        optRoutes6 = []
                    }
                    optRoutes6?.append((destination, prefix, gateway))
                }
                Regex.gateway.galixoArguments(in: line) {
                    optGateway4Arguments = $0
                }
                Regex.dns.galixoArguments(in: line) {
                    guard $0.count == 2 else {
                        return
                    }
                    if optDNSServers == nil {
                        optDNSServers = []
                    }
                    optDNSServers?.append($0[1])
                }
                Regex.domain.galixoArguments(in: line) {
                    guard $0.count == 2 else {
                        return
                    }
                    optDomain = $0[1]
                }
                Regex.domainSearch.galixoArguments(in: line) {
                    guard $0.count == 2 else {
                        return
                    }
                    if optSearchDomains == nil {
                        optSearchDomains = []
                    }
                    optSearchDomains?.append($0[1])
                }
                Regex.proxy.galixoArguments(in: line) {
                    if $0.count == 2 {
                        guard let url = URL(string: $0[1]) else {
                            unsupportedError = SettingsError.malformed(option: "dhcp-option PROXY_AUTO_CONFIG_URL has malformed URL")
                            return
                        }
                        optProxyAutoConfigurationURL = url
                        return
                    }

                    guard $0.count == 3, let port = UInt16($0[2]) else {
                        return
                    }
                    switch $0[0] {
                    case "PROXY_HTTPS":
                        optHTTPSProxy = GalixoServer($0[1], port)

                    case "PROXY_HTTP":
                        optHTTPProxy = GalixoServer($0[1], port)

                    default:
                        break
                    }
                }
                Regex.proxyBypass.galixoArguments(in: line) {
                    guard !$0.isEmpty else {
                        return
                    }
                    optProxyBypass = $0
                    optProxyBypass?.removeFirst()
                }
                Regex.redirectGateway.galixoArguments(in: line) {

                    // redirect IPv4 by default
                    optRedirectGateway = [.def1]

                    for arg in $0 {
                        guard let opt = RedirectGateway(rawValue: arg) else {
                            continue
                        }
                        optRedirectGateway?.insert(opt)
                    }
                }
                Regex.routeNoPull.galixoComponents(in: line) { _ in
                    optRouteNoPull = true
                }

                // MARK: Extra

                Regex.xorInfo.galixoArguments(in: line) {
                    isHandled = true
                    guard !$0.isEmpty else {
                        return
                    }

                    switch $0[0] {
                    case "xormask":
                        if $0.count > 1, let mask = $0[1].data(using: .utf8) {
                            optXorMethod = .xormask(mask: mask)
                        }

                    case "xorptrpos":
                        optXorMethod = .xorptrpos

                    case "reverse":
                        optXorMethod = .reverse

                    case "obfuscate":
                        if $0.count > 1, let mask = $0[1].data(using: .utf8) {
                            optXorMethod = .obfuscate(mask: mask)
                        }

                    default:
                        return
                    }
                }

                //

                if let error = unsupportedError {
                    throw error
                }
            }

            if isClient {
                guard let _ = optCA else {
                    throw SettingsError.missingConfiguration(option: "ca")
                }
                guard optCipher != nil || !(optDataCiphers?.isEmpty ?? false) else {
                    throw SettingsError.missingConfiguration(option: "cipher or data-ciphers")
                }
            }

            // MARK: Post-processing

            // ensure that non-nil network settings also imply non-empty
            if let array = optRoutes4 {
                assert(!array.isEmpty)
            }
            if let array = optRoutes6 {
                assert(!array.isEmpty)
            }
            if let array = optDNSServers {
                assert(!array.isEmpty)
            }
            if let array = optSearchDomains {
                assert(!array.isEmpty)
            }
            if let array = optProxyBypass {
                assert(!array.isEmpty)
            }

            //

            var sessionBuilder = ConfigurationBuilder()

            // MARK: General

            sessionBuilder.cipher = optDataCiphersFallback ?? optCipher
            sessionBuilder.dataCiphers = optDataCiphers
            sessionBuilder.digest = optDigest
            sessionBuilder.compressionFraming = optCompressionFraming
            sessionBuilder.compressionAlgorithm = optCompressionAlgorithm
            sessionBuilder.ca = optCA
            sessionBuilder.clientCertificate = optClientCertificate
            sessionBuilder.authUserPass = authUserPass

            if let clientKey = optClientKey, clientKey.isEncrypted {
                // FIXME: remove dependency on TLSBox
                guard let passphrase = passphrase, !passphrase.isEmpty else {
                    throw SettingsError.encryptionPassphrase
                }
                do {
                    sessionBuilder.clientKey = try clientKey.decrypted(with: passphrase)
                } catch {
                    throw SettingsError.unableToDecrypt(error: error)
                }
            } else {
                sessionBuilder.clientKey = optClientKey
            }

            if let keyLines = optTLSKeyLines, let strategy = optTLSStrategy {
                let optKey: FixedCreds?
                switch strategy {
                case .auth:
                    optKey = FixedCreds(lines: keyLines, direction: optKeyDirection)

                case .crypt:
                    optKey = FixedCreds(lines: keyLines, direction: .client)
                }
                if let key = optKey {
                    sessionBuilder.tlsWrap = TLSWrap(strategy: strategy, key: key)
                }
            }

            sessionBuilder.keepAliveInterval = optKeepAliveSeconds
            sessionBuilder.keepAliveTimeout = optKeepAliveTimeoutSeconds
            sessionBuilder.renegotiatesAfter = optRenegotiateAfterSeconds

            // MARK: Client

            optDefaultProto = optDefaultProto ?? .udp
            optDefaultPort = optDefaultPort ?? 1194
            if !optRemotes.isEmpty {
                var fullRemotes: [(String, UInt16, TotalServerCount)] = []
                optRemotes.forEach {
                    let hostname = $0.0
                    guard let port = $0.1 ?? optDefaultPort else {
                        return
                    }
                    guard let socketType = $0.2 ?? optDefaultProto else {
                        return
                    }
                    fullRemotes.append((hostname, port, socketType))
                }
                sessionBuilder.remotes = fullRemotes.map {
                    ServerConnectionDestination($0.0, .init($0.2, $0.1))
                }
            }

            sessionBuilder.authUserPass = authUserPass
            sessionBuilder.checksEKU = optChecksEKU
            sessionBuilder.randomizeEndpoint = optRandomizeEndpoint
            sessionBuilder.randomizeHostnames = optRandomizeHostnames
            sessionBuilder.mtu = optMTU

            // MARK: Server

            sessionBuilder.authToken = optAuthToken
            sessionBuilder.peerId = optPeerId

            // MARK: Routing

            //
            // excerpts from OpenVPN manpage
            //
            // "--ifconfig l rn":
            //
            // Set  TUN/TAP  adapter parameters.  l is the IP address of the local VPN endpoint.  For TUN devices in point-to-point mode, rn is the IP address of
            // the remote VPN endpoint.  For TAP devices, or TUN devices used with --topology subnet, rn is the subnet mask of the virtual network segment  which
            // is being created or connected to.
            //
            // "--topology mode":
            //
            // Note: Using --topology subnet changes the interpretation of the arguments of --ifconfig to mean "address netmask", no longer "local remote".
            //
            if let ifconfig4Arguments = optIfconfig4Arguments {
                guard ifconfig4Arguments.count == 2 else {
                    throw SettingsError.malformed(option: "ifconfig takes 2 arguments")
                }

                let address4: String
                let addressMask4: String
                let defaultGateway4: String

                let topology = Topology(rawValue: optTopology ?? "") ?? .net30
                switch topology {
                case .subnet:

                    // default gateway required when topology is subnet
                    guard let gateway4Arguments = optGateway4Arguments, gateway4Arguments.count == 1 else {
                        throw SettingsError.malformed(option: "route-gateway takes 1 argument")
                    }
                    address4 = ifconfig4Arguments[0]
                    addressMask4 = ifconfig4Arguments[1]
                    defaultGateway4 = gateway4Arguments[0]

                default:
                    address4 = ifconfig4Arguments[0]
                    addressMask4 = "255.255.255.255"
                    defaultGateway4 = ifconfig4Arguments[1]
                }

                sessionBuilder.ipv4 = IPv4Settings(
                    address: address4,
                    addressMask: addressMask4,
                    defaultGateway: defaultGateway4
                )
            }
            sessionBuilder.routes4 = optRoutes4?.map {
                IPv4Settings.Route($0.0, $0.1, $0.2)
            }

            if let ifconfig6Arguments = optIfconfig6Arguments {
                guard ifconfig6Arguments.count == 2 else {
                    throw SettingsError.malformed(option: "ifconfig-ipv6 takes 2 arguments")
                }
                let address6Components = ifconfig6Arguments[0].components(separatedBy: "/")
                guard address6Components.count == 2 else {
                    throw SettingsError.malformed(option: "ifconfig-ipv6 address must have a /prefix")
                }
                guard let addressPrefix6 = UInt8(address6Components[1]) else {
                    throw SettingsError.malformed(option: "ifconfig-ipv6 address prefix must be a 8-bit number")
                }

                let address6 = address6Components[0]
                let defaultGateway6 = ifconfig6Arguments[1]

                sessionBuilder.ipv6 = IPv6Settings(
                    address: address6,
                    addressPrefixLength: addressPrefix6,
                    defaultGateway: defaultGateway6
                )
            }
            sessionBuilder.routes6 = optRoutes6?.map {
                IPv6Settings.Route($0.0, $0.1, $0.2)
            }

            sessionBuilder.dnsServers = optDNSServers
            sessionBuilder.dnsDomain = optDomain
            sessionBuilder.searchDomains = optSearchDomains
            sessionBuilder.httpProxy = optHTTPProxy
            sessionBuilder.httpsProxy = optHTTPSProxy
            sessionBuilder.proxyAutoConfigurationURL = optProxyAutoConfigurationURL
            sessionBuilder.proxyBypassDomains = optProxyBypass
            if optRouteNoPull ?? false {
                sessionBuilder.noPullMask = [.routes, .dns, .proxy]
            }

            if let flags = optRedirectGateway {
                var policies: Set<RoutingPolicy> = []
                for opt in flags {
                    switch opt {
                    case .def1:
                        policies.insert(.IPv4)

                    case .ipv6:
                        policies.insert(.IPv6)

                    case .blockLocal:
                        policies.insert(.blockLocal)

                    default:
                        // TODO: handle [auto]local and block-*
                        continue
                    }
                }
                if flags.contains(.noIPv4) {
                    policies.remove(.IPv4)
                }
                sessionBuilder.routingPolicies = [RoutingPolicy](policies)
            }

            // MARK: Extra

            sessionBuilder.xorMethod = optXorMethod

            //

            return Result(
                url: originalURL,
                configuration: sessionBuilder.build(),
                strippedLines: optStrippedLines,
                warning: optWarning
            )
        }

        private static func normalizeEncryptedPEMBlock(block: inout [String]) {
    //        if block.count >= 1 && block[0].contains("ENCRYPTED") {
    //            return true
    //        }

            // XXX: restore blank line after encryption header (easier than tweaking trimmedLines)
            if block.count >= 3 && block[1].contains("Proc-Type") {
                block.insert("", at: 3)
    //            return true
            }
    //        return false
        }
    }
}

private extension String {
    func trimmedLines() -> [String] {
        return components(separatedBy: .newlines).map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
                .replacingOccurrences(of: "\\s", with: " ", options: .regularExpression)
        }.filter {
            !$0.isEmpty
        }
    }
}

private extension TotalServerCount {
    init?(protoString: String) {
        self.init(rawValue: protoString.uppercased())
    }
}
