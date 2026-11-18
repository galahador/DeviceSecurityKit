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
    
    private struct Constants {
        static let loggerSubsystem = "DylibInjectionDetector"

        static let envVarBytes: [UInt8] = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEA, 0x83, 0x22, 0xC2,
            0xEF, 0x15, 0x51, 0x4F, 0x4B, 0x04, 0x23, 0x12,
            0x5D, 0x9B, 0x55, 0x6F, 0x9B, 0xAB, 0x9F, 0xAB, 0xBA
        ]
        static let envVarSeparator: Character = ":"

        static let evidenceEnvVarLabel = "envVar"
        static let evidenceInjectedImageLabel = "injectedImage"
        static let evidenceLoadCommandLabel = "unexpectedLoadCommand"

        static let logEnvVarSet = "Dylib injection: DYLD_INSERT_LIBRARIES is set"
        static let logUnexpectedImage = "Dylib injection: unexpected loaded image: "
        static let logUnexpectedLoadCommand = "Dylib injection: unexpected LC_LOAD_DYLIB: "

        static let privatePrefix = "/private"
        static let privateVarPrefix = "/private/var/"
        static let pathSeparator = "/"

        static let systemPrefixes = ["/System/", "/usr/lib/", "/Developer/"]
        static let prebootPrefixes = ["/private/preboot/", "/private/var/preboot/", "/var/preboot/"]
        static let cryptexMarkers = ["/Cryptexes/", "/cryptex1/"]

        static let coreSimulatorPrefix = "/Library/Developer/CoreSimulator/"
        static let xcodeAppPrefix = "/Applications/Xcode"
        static let developerLibraryPrefix = "/Library/Developer/"

        static let relativePrefixes = ["@rpath/", "@executable_path/", "@loader_path/"]

        static func assignment(_ name: String, _ value: String) -> String {
            "\(name)=\(value)"
        }

        static func evidence(_ label: String, _ value: String) -> String {
            "\(label)(\"\(value)\")"
        }
    }
    
    private static let logger = SecurityLogger.security(subsystem: Constants.loggerSubsystem)
    private static let LC_LAZY_LOAD_DYLIB: UInt32 = 0x20

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

#if !DEBUG
        let o = StringObfuscator.shared
        let envVar = o.reveal(Constants.envVarBytes)
        if let value = unexpectedInsertedLibraries(envVar) {
            evidence.append(Constants.evidence(Constants.evidenceEnvVarLabel, Constants.assignment(envVar, value)))
        }
#endif

        let appBundlePath = Bundle.main.bundlePath
        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            guard let name = _dyld_get_image_name(i) else { continue }
            let path = String(cString: name)
            if !isExpectedImagePath(path, appBundlePath: appBundlePath) {
                evidence.append(Constants.evidence(Constants.evidenceInjectedImageLabel, path))
            }
        }

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
                            evidence.append(Constants.evidence(Constants.evidenceLoadCommandLabel, dylibPath))
                        }
                    }
                }
                cmdPtr = cmdPtr.advanced(by: Int(cmdsize))
            }
        }

        return evidence
#endif
    }

    private static func checkDYLDEnvironment() -> Bool {
#if DEBUG
        return false
#else
        let o = StringObfuscator.shared
        let envVar = o.reveal(Constants.envVarBytes)
        if unexpectedInsertedLibraries(envVar) != nil {
            logger.warning(Constants.logEnvVarSet)
            return true
        }
        return false
#endif
    }

    private static func unexpectedInsertedLibraries(_ envVar: String) -> String? {
        guard let val = getenv(envVar) else { return nil }
        let value = String(cString: val)
        let appBundlePath = Bundle.main.bundlePath
        let unexpected = value
            .split(separator: Constants.envVarSeparator)
            .map(String.init)
            .filter { !isExpectedImagePath($0, appBundlePath: appBundlePath) }
        return unexpected.isEmpty ? nil : value
    }

    private static func checkLoadedImages() -> Bool {
        let appBundlePath = Bundle.main.bundlePath
        let imageCount = _dyld_image_count()

        for i in 0..<imageCount {
            guard let name = _dyld_get_image_name(i) else { continue }
            let path = String(cString: name)

            if !isExpectedImagePath(path, appBundlePath: appBundlePath) {
                logger.warning(Constants.logUnexpectedImage + SecurityLogger.redact(path))
                return true
            }
        }

        return false
    }

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

            let nameOffset = Int(cmdPtr.load(fromByteOffset: 8, as: UInt32.self))
            guard nameOffset >= 12, nameOffset < Int(cmdsize) else { continue }
            let namePtr = cmdPtr.advanced(by: nameOffset).assumingMemoryBound(to: CChar.self)
            let dylibPath = String(cString: namePtr)

            if !isExpectedDylibPath(dylibPath) {
                logger.warning(Constants.logUnexpectedLoadCommand + SecurityLogger.redact(dylibPath))
                return true
            }
        }

        return false
    }

    private static func normalized(_ path: String) -> String {
        path.hasPrefix(Constants.privateVarPrefix) ? String(path.dropFirst(Constants.privatePrefix.count)) : path
    }

    private static func isSystemPath(_ path: String) -> Bool {
        if Constants.systemPrefixes.contains(where: path.hasPrefix) {
            return true
        }
        if Constants.prebootPrefixes.contains(where: path.hasPrefix) {
            return Constants.cryptexMarkers.contains(where: path.contains)
        }
        return false
    }

    private static func isInsideAppBundle(_ path: String, appBundlePath: String) -> Bool {
        func withSlash(_ p: String) -> String { p.hasSuffix(Constants.pathSeparator) ? p : p + Constants.pathSeparator }
        if normalized(path).hasPrefix(withSlash(normalized(appBundlePath))) {
            return true
        }
        let resolvedBundle = withSlash((appBundlePath as NSString).resolvingSymlinksInPath)
        return (path as NSString).resolvingSymlinksInPath.hasPrefix(resolvedBundle)
    }

    private static func isExpectedImagePath(_ path: String, appBundlePath: String) -> Bool {
        if isSystemPath(path) {
            return true
        }
        if isInsideAppBundle(path, appBundlePath: appBundlePath) {
            return true
        }
        if path.hasPrefix(Constants.coreSimulatorPrefix) {
            return true
        }
#if DEBUG
        if path.hasPrefix(Constants.xcodeAppPrefix) || path.hasPrefix(Constants.developerLibraryPrefix) {
            return true
        }
#endif
        return false
    }

    private static func isExpectedDylibPath(_ path: String) -> Bool {
        if Constants.relativePrefixes.contains(where: path.hasPrefix) {
            return true
        }
        if isSystemPath(path) {
            return true
        }
        return false
    }
}
