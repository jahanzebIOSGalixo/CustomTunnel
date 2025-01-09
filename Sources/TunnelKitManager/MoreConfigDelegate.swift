//
//  MoreConfigDelegate 2.swift
//  TunnelKit
//
//  Created by Jahanzeb  Macbook on 09/01/2025.
//

import NetworkExtension
public protocol MoreConfigDelegate {

    var title: String { get }
    func asTunnelProtocol(
        withBundleIdentifier bundleIdentifier: String,
        extra: MoreSetting?
    ) throws -> NETunnelProviderProtocol
}
