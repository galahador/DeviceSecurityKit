//
//  MDMDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 13/06/2026.
//

import Foundation

internal final class MDMDetector {

    private static let logger = SecurityLogger.security(subsystem: "MDMDetector")
    private static let o = StringObfuscator.shared

    // "com.apple.configuration.managed"
    private static let managedConfigurationKey = o.reveal([0x49, 0x53, 0xCC, 0xB2, 0x8E, 0x80, 0x06, 0x35, 0xFA, 0x09, 0x60, 0xDD, 0x10, 0xE1, 0x0E, 0x91, 0xCF, 0x99, 0x6C, 0x37, 0xFB, 0x07, 0x49, 0xEF, 0xE4, 0x60, 0x77, 0x8F, 0xB0, 0x25, 0x96, 0x5C, 0x47, 0xF4, 0x6E])

    // MARK: - Public

    /// Returns true if the app is running under a managed (MDM) configuration
    static func isManagedConfigurationPresent() -> Bool {
        guard let config = UserDefaults.standard.dictionary(forKey: managedConfigurationKey) else {
            return false
        }
        if !config.isEmpty {
            logger.info("Managed App Configuration detected — device/app is under MDM management")
            return true
        }
        return false
    }

    static func collectEvidence() -> [String] {
        var evidence: [String] = []
        if isManagedConfigurationPresent() {
            evidence.append("managedAppConfigurationPresent")
        }
        return evidence
    }
}
