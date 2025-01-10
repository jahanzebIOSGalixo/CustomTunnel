
import Foundation
import NetworkExtension
import TunnelKitCore
import TunnelKitOpenVPNCore

struct CustomConfigurations {
    let localOptions: OpenVPN.Configuration
    let remoteAddress: String
    let remoteOptions: OpenVPN.Configuration

    init(remoteAddress: String, localOptions: OpenVPN.Configuration, remoteOptions: OpenVPN.Configuration) {
        self.remoteAddress = remoteAddress
        self.localOptions = localOptions
        self.remoteOptions = remoteOptions
    }

    func createSettings() -> NEPacketTunnelNetworkSettings {
        let ipv4Configs = SettingsIPv4Calculated
        let settingsipv6 = settingsIPv6Calculated
        let settingsDns = computedDNSSettings
        let settingsProxy = computedProxySettings

        // add direct routes to DNS servers
        if !myWay {
            for server in settingsDns?.servers ?? [] {
                if server.contains(":") {
                    settingsipv6?.includedRoutes?.insert(NEIPv6Route(destinationAddress: server, networkPrefixLength: 128), at: 0)
                } else {
                    ipv4Configs?.includedRoutes?.insert(NEIPv4Route(destinationAddress: server, subnetMask: "255.255.255.255"), at: 0)
                }
            }
        }

        let galixoConfigs = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        galixoConfigs.ipv4Settings = ipv4Configs
        galixoConfigs.ipv6Settings = settingsipv6
        galixoConfigs.dnsSettings = settingsDns
        galixoConfigs.proxySettings = settingsProxy
        if let mtu = localOptions.mtu, mtu > 0 {
            galixoConfigs.mtu = NSNumber(value: mtu)
        }
        return galixoConfigs
    }
}

extension CustomConfigurations {
    private var pullProxy: Bool {
        !(localOptions.noPullMask?.contains(.proxy) ?? false)
    }
    private var pullRoutes: Bool {
        !(localOptions.noPullMask?.contains(.routes) ?? false)
    }
    private var pullDNS: Bool {
        !(localOptions.noPullMask?.contains(.dns) ?? false)
    }

   
}

extension CustomConfigurations {
    
    var myWay: Bool {
        isIPv4Gateway || isIPv6Gateway
    }

    private var path: [OpenVPN.RoutingPolicy]? {
        pullRoutes ? (remoteOptions.routingPolicies ?? localOptions.routingPolicies) : localOptions.routingPolicies
    }

    private var isIPv4Gateway: Bool {
        path?.contains(.IPv4) ?? false
    }

    private var isIPv6Gateway: Bool {
        path?.contains(.IPv6) ?? false
    }

    private var allRoutes4: [IPv4Settings.Route] {
        var routes = localOptions.routes4 ?? []
        if pullRoutes, let remoteRoutes = remoteOptions.routes4 {
            routes.append(contentsOf: remoteRoutes)
        }
        return routes
    }

    private var allRoutes6: [IPv6Settings.Route] {
        var routes = localOptions.routes6 ?? []
        if pullRoutes, let remoteRoutes = remoteOptions.routes6 {
            routes.append(contentsOf: remoteRoutes)
        }
        return routes
    }

    private var resolvingResolts: [String] {
        var servers = localOptions.dnsServers ?? []
        if pullDNS, let remoteServers = remoteOptions.dnsServers {
            servers.append(contentsOf: remoteServers)
        }
        return servers
    }

    private var dnsDomain: String? {
        var domain = localOptions.dnsDomain
        if pullDNS, let remoteDomain = remoteOptions.dnsDomain {
            domain = remoteDomain
        }
        return domain
    }

    private var allDNSSearchDomains: [String] {
        var searchDomains = localOptions.searchDomains ?? []
        if pullDNS, let remoteSearchDomains = remoteOptions.searchDomains {
            searchDomains.append(contentsOf: remoteSearchDomains)
        }
        return searchDomains
    }

    private var allProxyBypassDomains: [String] {
        var bypass = localOptions.proxyBypassDomains ?? []
        if pullProxy, let remoteBypass = remoteOptions.proxyBypassDomains {
            bypass.append(contentsOf: remoteBypass)
        }
        return bypass
    }
}

extension CustomConfigurations {
    
    func loadExcludedRoutes() -> [String] {
        let defaults = UserDefaults(suiteName: "group.galixo.BoltVpn")
        let isExcludedRoutesEnabled = defaults?.value(forKey: "isExcludedRoutesEnabled") as? Bool ?? false
        if isExcludedRoutesEnabled == true {
            let excludedRoutes = defaults?.value(forKey: "excludedRoutes") as? [String] ?? []
            return excludedRoutes
        }
        else {
            return []
        }
    }
    
    private var SettingsIPv4Calculated: NEIPv4Settings? {
        guard let ipv4 = remoteOptions.ipv4 else {
            return nil
        }
        let ipv4Settings = NEIPv4Settings(addresses: [ipv4.address], subnetMasks: [ipv4.addressMask])
        var neRoutes: [NEIPv4Route] = []

        // route all traffic to VPN?
        if isIPv4Gateway {
            let defaultRoute = NEIPv4Route.default()
            defaultRoute.gatewayAddress = ipv4.defaultGateway
            neRoutes.append(defaultRoute)

        }

        for r in allRoutes4 {
            let ipv4Route = NEIPv4Route(destinationAddress: r.destination, subnetMask: r.mask)
            let gw = r.gateway ?? ipv4.defaultGateway
            ipv4Route.gatewayAddress = gw
            neRoutes.append(ipv4Route)

        }

        ipv4Settings.includedRoutes = neRoutes

 let routes = loadExcludedRoutes()
       var excludedRoutes = [NEIPv4Route]()
        for item in routes {
            excludedRoutes.append(NEIPv4Route(destinationAddress: item, subnetMask: "255.255.255.255"))
        }
        ipv4Settings.excludedRoutes = excludedRoutes
        return ipv4Settings
    }
    
    var hasGateway: Bool {
        var hasGateway = false
        if isIPv4Gateway && remoteOptions.ipv4 != nil {
            hasGateway = true
        }
        if isIPv6Gateway && remoteOptions.ipv6 != nil {
            hasGateway = true
        }
        return hasGateway
    }
    
    private var settingsIPv6Calculated: NEIPv6Settings? {
        guard let ipv6 = remoteOptions.ipv6 else {
            return nil
        }
        let settingsOf6 = NEIPv6Settings(addresses: [ipv6.address], networkPrefixLengths: [ipv6.addressPrefixLength as NSNumber])
        var neRoutes: [NEIPv6Route] = []

        // route all traffic to VPN?
        if isIPv6Gateway {
            let defaultRoute = NEIPv6Route.default()
            defaultRoute.gatewayAddress = ipv6.defaultGateway
            neRoutes.append(defaultRoute)

        }

        for item in allRoutes6 {
            let ipv6Route = NEIPv6Route(destinationAddress: item.destination, networkPrefixLength: item.prefixLength as NSNumber)
            let gw = item.gateway ?? ipv6.defaultGateway
            ipv6Route.gatewayAddress = gw
            neRoutes.append(ipv6Route)

        }

        settingsOf6.includedRoutes = neRoutes
        settingsOf6.excludedRoutes = []
        return settingsOf6
    }
    
}

extension CustomConfigurations {
    
    
    private var computedDNSSettings: NEDNSSettings? {
        guard localOptions.isDNSEnabled ?? true else {
            return nil
        }
        var dnsSettings: NEDNSSettings?
        switch localOptions.dnsProtocol {
        case .https:
            let dnsServers = localOptions.dnsServers ?? []
            guard let serverURL = localOptions.dnsHTTPSURL else {
                break
            }
            let specific = NEDNSOverHTTPSSettings(servers: dnsServers)
            specific.serverURL = serverURL
            dnsSettings = specific



        case .tls:
            let dnsServers = localOptions.dnsServers ?? []
            guard let serverName = localOptions.dnsTLSServerName else {
                break
            }
            let specific = NEDNSOverTLSSettings(servers: dnsServers)
            specific.serverName = serverName
            dnsSettings = specific



        default:
            break
        }

        // fall back
        if dnsSettings == nil {
            let dnsServers = resolvingResolts
            if !dnsServers.isEmpty {

                dnsSettings = NEDNSSettings(servers: dnsServers)
            }
        }

        // "hack" for split DNS (i.e. use VPN only for DNS)
        if !myWay {
            dnsSettings?.matchDomains = [""]
        }

        if let domain = dnsDomain {

            dnsSettings?.domainName = domain
        }

        let routes = allDNSSearchDomains
        if !routes.isEmpty {

            dnsSettings?.searchDomains = routes
            if !myWay {
                dnsSettings?.matchDomains = dnsSettings?.searchDomains
            }
        }

        return dnsSettings
    }
}

extension CustomConfigurations {
    private var computedProxySettings: NEProxySettings? {
        guard localOptions.isProxyEnabled ?? true else {
            return nil
        }
        var proxySettings: NEProxySettings?
        if let myVpn = pullProxy ? (remoteOptions.httpsProxy ?? localOptions.httpsProxy) : localOptions.httpsProxy {
            proxySettings = NEProxySettings()
            proxySettings?.httpsServer = myVpn.neProxy()
            proxySettings?.httpsEnabled = true

        }
        if let httpProxy = pullProxy ? (remoteOptions.httpProxy ?? localOptions.httpProxy) : localOptions.httpProxy {
            if proxySettings == nil {
                proxySettings = NEProxySettings()
            }
            proxySettings?.httpServer = httpProxy.neProxy()
            proxySettings?.httpEnabled = true

        }
        if let pacURL = pullProxy ? (remoteOptions.proxyAutoConfigurationURL ?? localOptions.proxyAutoConfigurationURL) : localOptions.proxyAutoConfigurationURL {
            if proxySettings == nil {
                proxySettings = NEProxySettings()
            }
            proxySettings?.proxyAutoConfigurationURL = pacURL
            proxySettings?.autoProxyConfigurationEnabled = true

        }

        // only set if there is a proxy (proxySettings set to non-nil above)
        if proxySettings != nil {
            let bypass = allProxyBypassDomains
            if !bypass.isEmpty {
                proxySettings?.exceptionList = bypass

            }
        }
        return proxySettings
    }
}

private extension GalixoServer {
    func neProxy() -> NEProxyServer {
        return NEProxyServer(address: address, port: Int(port))
    }
}
