//
//  VPNProxyDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
import Darwin
import CFNetwork
import NetworkExtension

public final class VPNProxyDetector {

    private static let logger = SecurityLogger.security(subsystem: "VPNProxyDetector")
    private static let o = StringObfuscator.shared

    // MARK: - Public

    public static func isVPNOrProxyActive(allowedVPNBundleIDs: [String] = []) -> Bool {
        return checkVPNInterfaces(allowedBundleIDs: allowedVPNBundleIDs) || checkProxyConfiguration()
    }

    private static func checkVPNInterfaces(allowedBundleIDs: [String]) -> Bool {
        let manager = NEVPNManager.shared()
        let status = manager.connection.status

        guard status == .connected || status == .connecting || status == .reasserting else {
            return false
        }

        if !allowedBundleIDs.isEmpty,
           let proto = manager.protocolConfiguration {
            if let tunnelProto = proto as? NETunnelProviderProtocol,
               let tunnelBundleID = tunnelProto.providerBundleIdentifier,
               allowedBundleIDs.contains(tunnelBundleID) {
                logger.info("VPN connection allowed — bundle ID \(tunnelBundleID) is in allowlist")
                return false
            }
        }

        logger.warning("VPN connection detected via NEVPNManager: status \(status.rawValue)")
        return true
    }

    // MARK: - Check 2: System Proxy Settings

    private static func checkProxyConfiguration() -> Bool {
        return ProxyConfigurationChecker.isProxyConfigured()
    }
}
