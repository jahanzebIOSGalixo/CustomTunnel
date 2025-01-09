
import Foundation

public struct ResolveDnsRec {

    public let address: String
    public let isIPv6: Bool

    public init(address: String, isIPv6: Bool) {
        self.address = address
        self.isIPv6 = isIPv6
    }
}

public enum HostError: Error {
    case failure
    case timeout
}

public class SolverSND {

    private static let taks = DispatchQueue(label: "SolverSND")

   

    private static func handleHostResolution(for host: CFHost, queue: DispatchQueue, completion: @escaping (Result<[ResolveDnsRec], Error>) -> Void) {
        result(host: host) { result in
            queue.async {
                completion(result)
            }
        }
    }

    
    
    public static func dnsFromHost(_ hostname: String, timeout: Int, queue: DispatchQueue, completionHandler: @escaping (Result<[ResolveDnsRec], Error>) -> Void) {
        var pendingHandler: ((Result<[ResolveDnsRec], Error>) -> Void)? = completionHandler
        let host = CFHostCreateWithName(nil, hostname as CFString).takeRetainedValue()

        // Perform DNS resolution asynchronously
        SolverSND.taks.async {
            CFHostStartInfoResolution(host, .addresses, nil)
            guard let handler = pendingHandler else { return }
            handleHostResolution(for: host, queue: queue) { result in
                handler(result)
                pendingHandler = nil
            }
        }

        // Handle timeout
        queue.asyncAfter(deadline: .now() + .milliseconds(timeout)) {
            guard let handler = pendingHandler else { return }
            CFHostCancelInfoResolution(host, .addresses)
            handler(.failure(GalixoVpnError.dnsResolver(.timeout)))
            pendingHandler = nil
        }
    }

    private static func getHost(from rawAddress: Data) -> ResolveDnsRec? {
        var ipAddress = [CChar](repeating: 0, count: Int(NI_MAXHOST))

        let result = rawAddress.withUnsafeBytes { bytes in
            let addr = bytes.bindMemory(to: sockaddr.self).baseAddress!
            return getnameinfo(
                addr,
                socklen_t(rawAddress.count),
                &ipAddress,
                socklen_t(ipAddress.count),
                nil,
                0,
                NI_NUMERICHOST
            )
        }

        guard result == 0 else { return nil }

        let address = String(cString: ipAddress)
        let isIPv6 = rawAddress.count != 16
        return ResolveDnsRec(address: address, isIPv6: isIPv6)
    }

    
    private static func result(host: CFHost, completionHandler: @escaping (Result<[ResolveDnsRec], Error>) -> Void) {
        var success: DarwinBoolean = false

        guard let rawAddresses = CFHostGetAddressing(host, &success)?.takeUnretainedValue() as? [Data], success.boolValue else {
            completionHandler(.failure(GalixoVpnError.dnsResolver(.failure)))
            return
        }

        let records = rawAddresses.compactMap { addressData -> ResolveDnsRec? in
            return getHost(from: addressData)
        }

        guard !records.isEmpty else {
            completionHandler(.failure(GalixoVpnError.dnsResolver(.failure)))
            return
        }

        completionHandler(.success(records))
    }
    
    public static func string(fromIPv4 ipv4: UInt32) -> String {
        return stride(from: 24, through: 0, by: -8)
            .map { (ipv4 >> $0) & 0xFF }
            .map(String.init)
            .joined(separator: ".")
    }

    public static func ipv4(fromString string: String) -> UInt32? {
        var addr = in_addr()
        guard inet_pton(AF_INET, string, &addr) > 0 else { return nil }
        return CFSwapInt32BigToHost(addr.s_addr)
    }


}
