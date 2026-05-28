//
//  CertificatePinningDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
import Darwin
import CFNetwork
import MachO

public final class CertificatePinningDetector {

    private static let logger = SecurityLogger.security(subsystem: "CertificatePinningDetector")
    private static let o = StringObfuscator.shared

    // MARK: - Public
    public static func isPinningBypassed() -> Bool {
        return checkSecurityFrameworkIntegrity()
            || checkSSLBypassLibraries()
            || checkProxyConfiguration()
    }

    private static func checkSecurityFrameworkIntegrity() -> Bool {
        let functions = [
            o.reveal([0xB4, 0xEB, 0xE9, 0xD8, 0x88, 0x22, 0x10, 0xFB, 0x7F, 0x4C, 0x69, 0x71, 0x7C, 0x06, 0x69, 0x35, 0x25, 0x45, 0xAC, 0x50]),
            o.reveal([0x1C, 0xEE, 0xB0, 0x60, 0x65, 0x11, 0x03, 0xEC, 0x42, 0xDB, 0xC2, 0x52, 0x21, 0xE9, 0xE5, 0x68,
                      0x69, 0x7A, 0xD0, 0xCB, 0x1B, 0xA0, 0x99, 0x47, 0x65, 0xAD, 0xA8, 0xB2, 0x78]),
            o.reveal([0x38, 0xB8, 0x76, 0x28, 0x6B, 0xA5, 0xA6, 0xE2, 0x1B, 0x1A, 0xD7, 0x8F, 0x56, 0xFC, 0xFB, 0x93])
        ]

        let expectedPrefix = o.reveal([0xCE, 0x16, 0xC4, 0xB0, 0x81, 0xB5, 0xE9, 0xD1, 0x1C, 0x8D, 0x2C, 0x17,
            0x00, 0xDA, 0x0C, 0xD8, 0x1D, 0x85, 0xF7, 0x33, 0xB0, 0x51, 0x30, 0x6E,
            0x63, 0x06, 0x41, 0xA3, 0x1B, 0xC3, 0xA4, 0xB3, 0x06, 0x83, 0x94, 0x27,
            0x8E, 0xC6, 0x5A, 0x83, 0xA4, 0x83, 0x49, 0xF8, 0x88, 0xC9, 0x78, 0x5A,
            0x57])

        guard let handle = dlopen(nil, RTLD_NOW) else { return false }
        defer { dlclose(handle) }

        for name in functions {
            guard let sym = dlsym(handle, name) else { continue }

            var info = Dl_info()
            guard dladdr(sym, &info) != 0, let fname = info.dli_fname else {
                logger.warning("Pinning check: cannot resolve image for \(name) — treating as suspicious")
                return true
            }

            let imagePath = String(cString: fname)
            if !imagePath.hasPrefix(expectedPrefix) {
                logger.warning("Pinning bypass: \(name) redirected to: \(imagePath)")
                return true
            }
        }

        return false
    }

    private static func checkSSLBypassLibraries() -> Bool {
        let bypassLibraries = [
            o.reveal([0x03, 0xF1, 0xCC, 0xD3, 0xB9, 0xF6, 0x62, 0x9A, 0xF1, 0x87, 0xBF, 0x24, 0x93, 0x05, 0x40, 0x39, 0x53, 0xB2]),
            o.reveal([0xAC, 0x3A, 0x5F, 0xC7, 0x54, 0x06, 0xB9, 0xC4, 0x2E, 0x86, 0xCC, 0xFF, 0xB2, 0x90, 0xEC, 0xD7, 0x85, 0xE8, 0x4F]),
            o.reveal([0x79, 0xA1, 0x76, 0xD3, 0x5B, 0x65, 0xD9, 0x9C, 0x51, 0x64, 0x2B, 0x15, 0x11, 0xF5, 0x26, 0x1F, 0xF2, 0x56])
        ]

        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            guard let rawName = _dyld_get_image_name(i) else { continue }
            let imageName = String(cString: rawName).lowercased()

            for lib in bypassLibraries {
                if imageName.contains(lib.lowercased()) {
                    logger.warning("SSL bypass library detected: \(imageName)")
                    return true
                }
            }
        }

        return false
    }

    private static func checkProxyConfiguration() -> Bool {
        guard let rawSettings = CFNetworkCopySystemProxySettings() else { return false }
        let settings = rawSettings.takeRetainedValue() as NSDictionary

        let httpKey  = o.reveal([0x83, 0x50, 0xE6, 0x48, 0xF8, 0x6B, 0x66, 0x37, 0xD7, 0x23, 0xBA, 0xD3, 0x84, 0xC8])
        let httpsKey = o.reveal([0xE6, 0x8D, 0x79, 0xA5, 0x50, 0xF1, 0x0A, 0x6D, 0x61, 0x16, 0x43, 0xCA, 0x92, 0x01, 0xD2])

        let httpEnabled  = (settings[httpKey]  as? Int) == 1
        let httpsEnabled = (settings[httpsKey] as? Int) == 1

        if httpEnabled || httpsEnabled {
            logger.warning("HTTP/HTTPS proxy detected — possible MITM setup")
            return true
        }

        return false
    }
}
