//
//  DylibInjectionDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 30/05/2026.
//

import Foundation
import Darwin
import MachO

public final class DylibInjectionDetector {

    private static let logger = SecurityLogger.security(subsystem: "DylibInjectionDetector")

    /// Not defined in the MachO Swift module; value from `<mach-o/loader.h>`.
    private static let LC_LAZY_LOAD_DYLIB: UInt32 = 0x20

    // MARK: - Public

    public static func isDylibInjected() -> Bool {
#if targetEnvironment(simulator)
        return false
#else
        return checkDYLDEnvironment() || checkLoadedImages() || checkMainBinaryLoadCommands()
#endif
    }

    public static func collectEvidence() -> [String] {
#if targetEnvironment(simulator)
        return []
#else
        var evidence: [String] = []

        // DYLD_INSERT_LIBRARIES
#if !DEBUG
        let o = StringObfuscator.shared
        let envVar = o.reveal([
            0xAA, 0xBB, 0xCC, 0xDD, 0xEA, 0x83, 0x22, 0xC2,
            0xEF, 0x15, 0x51, 0x4F, 0x4B, 0x04, 0x23, 0x12,
            0x5D, 0x9B, 0x55, 0x6F, 0x9B, 0xAB, 0x9F, 0xAB, 0xBA
        ])
        if let val = getenv(envVar) {
            let value = String(cString: val)
            if !value.isEmpty {
                evidence.append("envVar(\"\(envVar)=\(value)\")")
            }
        }
#endif

        // Loaded images
        let appBundlePath = Bundle.main.bundlePath
        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            guard let name = _dyld_get_image_name(i) else { continue }
            let path = String(cString: name)
            if !isExpectedImagePath(path, appBundlePath: appBundlePath) {
                evidence.append("injectedImage(\"\(path)\")")
            }
        }

        // LC_LOAD_DYLIB commands
        if let header = _dyld_get_image_header(0) {
            let rawPtr = UnsafeRawPointer(header)
            let magic = rawPtr.load(as: UInt32.self)
            let headerSize: Int
            let ncmds: UInt32
            if magic == MH_MAGIC_64 {
                headerSize = MemoryLayout<mach_header_64>.size
                ncmds = rawPtr.load(fromByteOffset: MemoryLayout.offset(of: \mach_header_64.ncmds)!, as: UInt32.self)
            } else if magic == MH_MAGIC {
                headerSize = MemoryLayout<mach_header>.size
                ncmds = rawPtr.load(fromByteOffset: MemoryLayout.offset(of: \mach_header.ncmds)!, as: UInt32.self)
            } else {
                return evidence
            }

            var cmdPtr = rawPtr.advanced(by: headerSize)
            for _ in 0..<ncmds {
                let cmd = cmdPtr.load(as: UInt32.self)
                let cmdsize = cmdPtr.load(fromByteOffset: 4, as: UInt32.self)
                guard cmdsize >= 12 else { break }

                if cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB || cmd == LC_REEXPORT_DYLIB || cmd == LC_LAZY_LOAD_DYLIB {
                    let nameOffset = Int(cmdPtr.load(fromByteOffset: 8, as: UInt32.self))
                    if nameOffset >= 12, nameOffset < Int(cmdsize) {
                        let namePtr = cmdPtr.advanced(by: nameOffset).assumingMemoryBound(to: CChar.self)
                        let dylibPath = String(cString: namePtr)
                        if !isExpectedDylibPath(dylibPath) {
                            evidence.append("unexpectedLoadCommand(\"\(dylibPath)\")")
                        }
                    }
                }
                cmdPtr = cmdPtr.advanced(by: Int(cmdsize))
            }
        }

        return evidence
#endif
    }

    // MARK: - Check 1: DYLD_INSERT_LIBRARIES environment variable

    private static func checkDYLDEnvironment() -> Bool {
#if DEBUG
        return false
#else
        let o = StringObfuscator.shared
        let envVar = o.reveal([
            0xAA, 0xBB, 0xCC, 0xDD, 0xEA, 0x83, 0x22, 0xC2,
            0xEF, 0x15, 0x51, 0x4F, 0x4B, 0x04, 0x23, 0x12,
            0x5D, 0x9B, 0x55, 0x6F, 0x9B, 0xAB, 0x9F, 0xAB, 0xBA
        ])
        if let val = getenv(envVar), String(cString: val).count > 0 {
            logger.warning("Dylib injection: DYLD_INSERT_LIBRARIES is set")
            return true
        }
        return false
#endif
    }

    // MARK: - Check 2: Audit all loaded dyld images for non-system, non-app paths

    private static func checkLoadedImages() -> Bool {
        let appBundlePath = Bundle.main.bundlePath
        let imageCount = _dyld_image_count()

        for i in 0..<imageCount {
            guard let name = _dyld_get_image_name(i) else { continue }
            let path = String(cString: name)

            if !isExpectedImagePath(path, appBundlePath: appBundlePath) {
                logger.warning("Dylib injection: unexpected loaded image: \(SecurityLogger.redact(path))")
                return true
            }
        }

        return false
    }

    // MARK: - Check 3: Parse main executable's load commands for unexpected LC_LOAD_DYLIB entries

    private static func checkMainBinaryLoadCommands() -> Bool {
        guard let header = _dyld_get_image_header(0) else { return false }

        let rawPtr = UnsafeRawPointer(header)
        let magic = rawPtr.load(as: UInt32.self)

        let headerSize: Int
        let ncmds: UInt32
        if magic == MH_MAGIC_64 {
            headerSize = MemoryLayout<mach_header_64>.size
            ncmds = rawPtr.load(fromByteOffset: MemoryLayout.offset(of: \mach_header_64.ncmds)!, as: UInt32.self)
        } else if magic == MH_MAGIC {
            headerSize = MemoryLayout<mach_header>.size
            ncmds = rawPtr.load(fromByteOffset: MemoryLayout.offset(of: \mach_header.ncmds)!, as: UInt32.self)
        } else {
            return false
        }

        var cmdPtr = rawPtr.advanced(by: headerSize)

        for _ in 0..<ncmds {
            let cmd = cmdPtr.load(as: UInt32.self)
            let cmdsize = cmdPtr.load(fromByteOffset: 4, as: UInt32.self)
            guard cmdsize >= 12 else { break }
            defer { cmdPtr = cmdPtr.advanced(by: Int(cmdsize)) }

            guard cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB || cmd == LC_REEXPORT_DYLIB || cmd == LC_LAZY_LOAD_DYLIB else { continue }

            // dylib_command: cmd(4) + cmdsize(4) + name_offset(4) + timestamp(4) + versions(8)
            let nameOffset = Int(cmdPtr.load(fromByteOffset: 8, as: UInt32.self))
            guard nameOffset >= 12, nameOffset < Int(cmdsize) else { continue }
            let namePtr = cmdPtr.advanced(by: nameOffset).assumingMemoryBound(to: CChar.self)
            let dylibPath = String(cString: namePtr)

            if !isExpectedDylibPath(dylibPath) {
                logger.warning("Dylib injection: unexpected LC_LOAD_DYLIB: \(SecurityLogger.redact(dylibPath))")
                return true
            }
        }

        return false
    }

    // MARK: - Path Validation

    private static func isExpectedImagePath(_ path: String, appBundlePath: String) -> Bool {
        // App bundle (main executable + embedded frameworks)
        if path.hasPrefix(appBundlePath) {
            return true
        }
        // System frameworks and libraries
        if path.hasPrefix("/System/") || path.hasPrefix("/usr/lib/") {
            return true
        }
        // CoreSimulator runtime (simulator-hosted system libs resolve here)
        if path.hasPrefix("/Library/Developer/CoreSimulator/") {
            return true
        }
#if DEBUG
        // Xcode injected libs (hot reload, sanitizers, etc.)
        if path.hasPrefix("/Applications/Xcode") || path.hasPrefix("/Library/Developer/") {
            return true
        }
#endif
        return false
    }

    private static func isExpectedDylibPath(_ path: String) -> Bool {
        // Relative paths resolved by dyld at load time — normal for embedded frameworks
        if path.hasPrefix("@rpath/") || path.hasPrefix("@executable_path/") || path.hasPrefix("@loader_path/") {
            return true
        }
        // System paths
        if path.hasPrefix("/System/") || path.hasPrefix("/usr/lib/") {
            return true
        }
        return false
    }
}
