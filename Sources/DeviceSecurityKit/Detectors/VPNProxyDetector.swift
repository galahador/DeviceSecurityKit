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
        guard let rawSettings = CFNetworkCopySystemProxySettings() else { return false }
        let settings = rawSettings.takeRetainedValue() as NSDictionary

        let enableKeys = [
            o.reveal([0x59, 0x3A, 0xF1, 0xD8, 0xE2, 0xC6, 0x46, 0x3A, 0xD1, 0xBA, 0xBC, 0xDA, 0xAE, 0x93]),
            o.reveal([0x29, 0x13, 0xB3, 0x0E, 0xF1, 0x60, 0xF9, 0x88, 0x8C, 0xC3, 0x96, 0x5B, 0xDB, 0xDC, 0x94]),
            o.reveal([0x6B, 0xC8, 0xB0, 0x34, 0xB7, 0xAE, 0x5D, 0x62, 0x8D, 0x5A, 0x0D, 0xFE, 0xC6, 0x4F, 0xA0]),
        ]

        let hostKeys = [
            o.reveal([0x9A, 0x7D, 0x9C, 0xE4, 0x01, 0xAE, 0x67, 0x46, 0x6B, 0x42, 0xEB, 0xC4, 0x1E]),
            o.reveal([0x7C, 0x51, 0x01, 0xEB, 0xDA, 0x63, 0x58, 0xD3, 0x8B, 0x2D, 0x41, 0x7E, 0x6A, 0xD2]),
            o.reveal([0xDB, 0x03, 0x6D, 0xB6, 0xF2, 0x13, 0xBE, 0x03, 0x24, 0x3E, 0xDE, 0xD9, 0x59, 0x1B]),
        ]

        for key in enableKeys {
            if (settings[key] as? Int) == 1 {
                logger.warning("Proxy enabled — key: \(key)")
                return true
            }
        }

        for key in hostKeys {
            if let host = settings[key] as? String, !host.isEmpty {
                logger.warning("Proxy host configured — key: \(key), host: \(host)")
                return true
            }
        }

        return false
    }
}
