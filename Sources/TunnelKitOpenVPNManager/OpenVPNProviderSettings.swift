//
//  OpenVPN+ProviderConfiguration.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 3/6/22.
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
import TunnelKitManager
import TunnelKitCore
import TunnelKitOpenVPNCore
import NetworkExtension

import __TunnelKitUtils



extension OpenVPN {

    public struct Settings: Codable {
        fileprivate enum Keys: String {
            case logPath = "OpenVPN.LogPath"
            case dataCount = "OpenVPN.DataCount"
            case serverConfiguration = "OpenVPN.ServerConfiguration"
            case lastError = "OpenVPN.LastError"
        }

        public var debugLogPath: String?
        public var shouldDebug = false
        public let configuration: OpenVPN.Configuration
        public var masksPrivateData = true
        public var username: String?
        public let appGroup: String
        public var debugLogFormat: String?
        public let title: String
        public var versionIdentifier: String?

        public init(_ title: String, appGroup: String, configuration: OpenVPN.Configuration) {
            self.title = title
            self.appGroup = appGroup
            self.configuration = configuration
        }

        public func print() {
            configuration.print(isLocal: true)
        }
    }


}

// MARK: NetworkExtensionConfiguration

extension OpenVPN.Settings: MoreConfigDelegate {

    public func asTunnelProtocol(
        withBundleIdentifier tunnelBundleIdentifier: String,
        extra: MoreSetting?
    ) throws -> NETunnelProviderProtocol {
        guard let firstRemote = configuration.remotes?.first else {
            preconditionFailure("No remotes set")
        }

        let config = NETunnelProviderProtocol()
        config.providerBundleIdentifier = tunnelBundleIdentifier
        config.serverAddress = "\(firstRemote.address):\(firstRemote.proto.port)"
        if let username = username {
            config.username = username
            config.passwordReference = extra?.passwordReference
        }
#if !os(tvOS)
        config.includeAllNetworks = extra?.killSwitch ?? false
#endif
        config.disconnectOnSleep = extra?.disconnectsOnSleep ?? false
        config.providerConfiguration = try convertToKeyValue()
       
        return config
    }
    
}

// MARK: Shared data

extension OpenVPN.Settings {
    public var serverConfiguration: OpenVPN.Configuration? {
        return defaults?.serverSettings
    }

    public var lastError: GalixoTunnelErrors? {
        return defaults?.finalError
    }

    public var urlForDebugLog: URL? {
        return defaults?.openVPNURLForDebugLog(appGroup: appGroup)
    }

    public var dataCount: DataCount? {
        return defaults?.dataLength
    }

    private var defaults: UserDefaults? {
        return UserDefaults(suiteName: appGroup)
    }
}


extension OpenVPN.Settings {
    public func _appexSetDataCount(_ newValue: DataCount?) {
        defaults?.dataLength = newValue
    }

    public func _appexSetServerConfiguration(_ newValue: OpenVPN.Configuration?) {
        defaults?.serverSettings = newValue
    }

    public func _appexSetLastError(_ newValue: GalixoTunnelErrors?) {
        defaults?.finalError = newValue
    }

    public var _appexDebugLogURL: URL? {
        guard let path = debugLogPath else {
            return nil
        }
        return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
            .appendingPathComponent(path)
    }

    public func _appexSetDebugLogPath() {
        defaults?.setValue(debugLogPath, forKey: OpenVPN.Settings.Keys.logPath.rawValue)
    }
}

extension UserDefaults {
    public fileprivate(set) var dataLength: DataCount? {
        get {
            guard let rawValue = dataLengths else {
                return nil
            }
            guard rawValue.count == 2 else {
                return nil
            }
            return DataCount(rawValue[0], rawValue[1])
        }
        set {
            guard let newValue = newValue else {
                getDataCounts()
                return
            }
            dataLengths = [newValue.received, newValue.sent]
        }
    }

    public fileprivate(set) var serverSettings: OpenVPN.Configuration? {
        get {
            guard let raw = data(forKey: OpenVPN.Settings.Keys.serverConfiguration.rawValue) else {
                return nil
            }
            let decoder = JSONDecoder()
            do {
                let cfg = try decoder.decode(OpenVPN.Configuration.self, from: raw)
                return cfg
            } catch {
                return nil
            }
        }
        set {
            guard let newValue = newValue else {
                return
            }
            let encoder = JSONEncoder()
            do {
                let raw = try encoder.encode(newValue)
                set(raw, forKey: OpenVPN.Settings.Keys.serverConfiguration.rawValue)
            } catch {

            }
        }
    }

    private func getDataCounts() {
        removeObject(forKey: OpenVPN.Settings.Keys.dataCount.rawValue)
    }

    @objc private var dataLengths: [UInt]? {
        get {
            return array(forKey: OpenVPN.Settings.Keys.dataCount.rawValue) as? [UInt]
        }
        set {
            set(newValue, forKey: OpenVPN.Settings.Keys.dataCount.rawValue)
        }
    }

    public fileprivate(set) var finalError: GalixoTunnelErrors? {
        get {
            guard let rawValue = string(forKey: OpenVPN.Settings.Keys.lastError.rawValue) else {
                return nil
            }
            return GalixoTunnelErrors(rawValue: rawValue)
        }
        set {
            guard let newValue = newValue else {
                removeObject(forKey: OpenVPN.Settings.Keys.lastError.rawValue)
                return
            }
            set(newValue.rawValue, forKey: OpenVPN.Settings.Keys.lastError.rawValue)
        }
    }

    public func openVPNURLForDebugLog(appGroup: String) -> URL? {
        guard let path = string(forKey: OpenVPN.Settings.Keys.logPath.rawValue) else {
            return nil
        }
        return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
            .appendingPathComponent(path)
    }
}

