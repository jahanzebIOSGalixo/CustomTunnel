

import Foundation

import TunnelKitCore
import TunnelKitOpenVPNCore
import CTunnelKitCore
import CTunnelKitOpenVPNProtocol



fileprivate extension ZeroingData {
    func appendSized(_ buf: ZeroingData) {
        append(Z(UInt16(buf.count).bigEndian))
        append(buf)
    }
}

extension OpenVPN {
    class CredentialsAut {
        var withLocalOptions: Bool
        private(set) var serverRandom1: ZeroingData?
        private var controlBuffer: ZeroingData

        private(set) var preMaster: ZeroingData

        private(set) var password: ZeroingData?

        private(set) var random2: ZeroingData

        

        private(set) var serverRandom2: ZeroingData?
        private(set) var random1: ZeroingData
        private(set) var username: ZeroingData?

        init(_ username: String?, _ password: String?) throws {
            controlBuffer = Z()

            // XXX: not 100% secure, can't erase input username/password
            if let username = username, let password = password {
                self.username = Z(username, nullTerminated: true)
                self.password = Z(password, nullTerminated: true)
            } else {
                self.username = nil
                self.password = nil
            }

            preMaster = try SecureRandom.safeData(length: OpenVpnMainConfig.OpenVPN.postFix)
            random1 = try SecureRandom.safeData(length: OpenVpnMainConfig.OpenVPN.totalLength)
            random2 = try SecureRandom.safeData(length: OpenVpnMainConfig.OpenVPN.totalLength)
            
            withLocalOptions = true

        }
        
        func getMessages() -> [String] {
            var messages = [String]()
            var offset = 0

            while true {
                guard let msg = controlBuffer.nullTerminatedString(fromOffset: offset) else {
                    break
                }
                messages.append(msg)
                offset += msg.count + 1
            }

            controlBuffer.remove(untilOffset: offset)

            return messages
        }

        func reset() {
            username = nil
            password = nil
            controlBuffer.zero()
            preMaster.zero()
           
            serverRandom1?.zero()
            serverRandom2?.zero()
            random1.zero()
            random2.zero()
        }
        
        func getResponse() throws -> Bool {
            let prefixLength = CountTime.dnsPost.count

            // TLS prefix + random (x2) + opts length [+ opts]
            guard controlBuffer.count >= prefixLength + 2 * OpenVpnMainConfig.OpenVPN.totalLength + 2 else {
                return false
            }

            let prefix = controlBuffer.withOffset(0, count: prefixLength)
            guard prefix.isEqual(to: CountTime.dnsPost) else {
                throw VpnErrors.wrongControlDataPrefix
            }

            var offset = CountTime.dnsPost.count

            let serverRandom1 = controlBuffer.withOffset(offset, count: OpenVpnMainConfig.OpenVPN.totalLength)
            offset += OpenVpnMainConfig.OpenVPN.totalLength

            let serverRandom2 = controlBuffer.withOffset(offset, count: OpenVpnMainConfig.OpenVPN.totalLength)
            offset += OpenVpnMainConfig.OpenVPN.totalLength

            let serverOptsLength = Int(controlBuffer.networkUInt16Value(fromOffset: offset))
            offset += 2

            guard controlBuffer.count >= offset + serverOptsLength else {
                return false
            }
            let serverOpts = controlBuffer.withOffset(offset, count: serverOptsLength)
            offset += serverOptsLength

            if OpenVpnMainConfig.logsSensitiveData {

            } else {

            }

            if let serverOptsString = serverOpts.nullTerminatedString(fromOffset: 0) {

            }

            self.serverRandom1 = serverRandom1
            self.serverRandom2 = serverRandom2
            controlBuffer.remove(untilOffset: offset)

            return true
        }

        func validator(tls: TLSBox, with: Configuration) throws {
            let raw = Z(CountTime.dnsPost)

            // local keys
            raw.append(preMaster)
            raw.append(random1)
            raw.append(random2)

            // options string
            let optsString: String
            if withLocalOptions {
                var opts = [
                    "V4",
                    "dev-type tun"
                ]
                if let comp = with.compressionFraming {
                    switch comp {
                    case .compLZO:
                        opts.append("comp-lzo")

                    case .compress:
                        opts.append("compress")

                    default:
                        break
                    }
                }
                if let direction = with.tlsWrap?.key.direction?.rawValue {
                    opts.append("keydir \(direction)")
                }
                opts.append("cipher \(with.fallbackCipher.rawValue)")
                opts.append("auth \(with.fallbackDigest.rawValue)")
                opts.append("keysize \(with.fallbackCipher.keySize)")
                if let strategy = with.tlsWrap?.strategy {
                    opts.append("tls-\(strategy)")
                }
                opts.append("key-method 2")
                opts.append("tls-client")
                optsString = opts.joined(separator: ",")
            } else {
                optsString = "V0 UNDEF"
            }

            raw.appendSized(Z(optsString, nullTerminated: true))

            // credentials
            if let username = username, let password = password {
                raw.appendSized(username)
                raw.appendSized(password)
            } else {
                raw.append(Z(UInt16(0)))
                raw.append(Z(UInt16(0)))
            }

            // peer info
            var extra: [String: String] = [:]
            if let dataCiphers = with.dataCiphers {
                extra["IV_CIPHERS"] = dataCiphers.map(\.rawValue).joined(separator: ":")
            }
            raw.appendSized(Z(OpenVpnMainConfig.OpenVPN.platformCheck(moreSettings: extra), nullTerminated: true))

            if OpenVpnMainConfig.logsSensitiveData {

            } else {

            }

            try tls.putRawPlainText(raw.bytes, length: raw.count)
        }

        // MARK: Server replies

        func appendinnerData(_ data: ZeroingData) {
            controlBuffer.append(data)
        }

        

        
    }
}
