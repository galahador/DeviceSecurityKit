//
//  HookDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
import Darwin
import MachO

public final class HookDetector {

    private static let logger = SecurityLogger.security(subsystem: "HookDetector")
    private static let o = StringObfuscator.shared

    // MARK: - Public

    public static func isFunctionHooked() -> Bool {
        return checkSystemFunctionOrigins()
            || checkFunctionPrologues()
    }

    private static func checkSystemFunctionOrigins() -> Bool {
        let functionNames = [
            o.reveal([0xCE, 0xA8, 0x2F, 0x47, 0xE6, 0x3A, 0xD8, 0xBC, 0x1F, 0x1D]),
            o.reveal([0xBF, 0x61, 0xDF, 0xCF, 0x21, 0x57, 0xCC, 0xEB, 0xFA, 0x46]),
            o.reveal([0x64, 0xFC, 0x2A, 0x29, 0x9C, 0x13, 0x5B, 0x0A, 0x44, 0x88]),
            o.reveal([0x96, 0x43, 0x61, 0x2A, 0xA2, 0xE8, 0x6D, 0x89, 0xBB, 0xFE, 0xA4]),
            o.reveal([0x43, 0x35, 0x4A, 0x3A, 0x18, 0x87, 0x3C, 0xF3, 0x69, 0x76, 0x93, 0x5C, 0xBE, 0x92, 0x32, 0x05, 0x66, 0x26, 0xB2, 0xAA, 0x1C]),
            o.reveal([0xCD, 0x40, 0x98, 0x3C, 0x0B, 0x7B, 0x07, 0x1B, 0x42, 0xFA, 0xA4, 0x70, 0x88, 0x5C, 0x8E, 0x7C, 0x1F, 0x3C, 0xFE, 0x48, 0x17, 0x6B, 0xFE, 0x28])
        ]

        let systemPrefixes = [
            o.reveal([0xA9, 0xBE, 0x53, 0x9D, 0xDE, 0x11, 0x60, 0x66, 0xDC, 0x8A, 0x87, 0xDC, 0xEC]),
            o.reveal([0x62, 0x2E, 0x26, 0x13, 0x48, 0x9F, 0xA6, 0xE7, 0x29, 0xAB, 0x7D, 0xD1, 0x63, 0x9D, 0x63, 0x58, 0xBB, 0x06, 0x9C, 0x39]),
            o.reveal([0x28, 0x24, 0x55, 0xF6, 0x2D, 0xFB, 0x67, 0xF1, 0x82, 0x24, 0xAF, 0x48, 0x6F, 0x99, 0x76, 0x40, 0x75, 0x29, 0x95])
        ]

        guard let handle = dlopen(nil, RTLD_NOW) else { return false }
        defer { dlclose(handle) }

        for name in functionNames {
            guard let sym = dlsym(handle, name) else { continue }

            var info = Dl_info()
            guard dladdr(sym, &info) != 0, let fname = info.dli_fname else {
                logger.warning("Hook check: could not resolve image for function — treating as suspicious")
                return true
            }

            let imagePath = String(cString: fname)
            if !systemPrefixes.contains(where: { imagePath.hasPrefix($0) }) {
                logger.warning("Hook detected: function redirected to non-system image: \(imagePath)")
                return true
            }
        }

        return false
    }

    private static func checkFunctionPrologues() -> Bool {
#if arch(arm64)
        guard let handle = dlopen(nil, RTLD_NOW) else { return false }
        defer { dlclose(handle) }

        // Obfuscated: "sysctl", "getenv"
        let targets = [
            o.reveal([0xE0, 0x9D, 0x26, 0x98, 0x3E, 0x17, 0xC4, 0x41, 0x23, 0x40]),
            o.reveal([0x6F, 0xC6, 0xBB, 0x48, 0xC1, 0xBB, 0x32, 0x73, 0xBE, 0x56])
        ]

        for name in targets {
            guard let sym = dlsym(handle, name) else { continue }

            let instructions = UnsafeRawPointer(sym).assumingMemoryBound(to: UInt32.self)
            let first  = instructions.pointee
            let second = instructions.advanced(by: 1).pointee

            // Frida trampoline: LDR X16, #8 + BR X16
            if first == 0x58000050 && second == 0xD61F0200 {
                logger.warning("Frida inline hook trampoline detected on: \(name)")
                return true
            }

            // Generic unconditional branch at function start
            if (first & 0xFC000000) == 0x14000000 {
                logger.warning("Suspicious unconditional branch at start of: \(name)")
                return true
            }
        }
#endif
        return false
    }
}
