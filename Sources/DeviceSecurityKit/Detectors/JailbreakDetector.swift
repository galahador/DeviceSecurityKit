//
//  JailbreakDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
import UIKit
import Darwin
import MachO

public final class JailbreakDetector {

    private struct Constants {
        static let loggerSubsystem = "JailbreakDetector"

        static let dyldPrefix = "DYLD_"
        static let prebootMarker = "preboot"
        static let jailbreakRootMarker = "/var/jb"
        static let jailbreakMarkerFile = "jb"
        static let forkSymbol = "fork"
        static let sandboxProbeContent = "test"

        static let evidenceSandboxEscape = "sandboxEscapeWritable"
        static let evidenceForkSucceeded = "forkSucceeded"

        static let urlSchemeCheckSkipped = "URL scheme check skipped — checker unavailable (simulator, or LSApplicationQueriesSchemes not configured in Info.plist)"
        static let antiDetectionTweakLog = "Anti-jailbreak-detection tweak detected in loaded images"

        static func suspiciousPath(_ path: String) -> String { "suspiciousPath(\"\(path)\")" }
        static func urlSchemeResponds(_ scheme: String) -> String { "urlSchemeResponds(\"\(scheme)\")" }
        static func symbolicLink(_ path: String) -> String { "symbolicLink(\"\(path)\")" }
        static func envVarEvidence(_ name: String) -> String { "envVar(\"\(name)\")" }
        static func antiDetectionTool(_ path: String) -> String { "antiDetectionTool(\"\(path)\")" }
        static func prebootPathEvidence(_ path: String) -> String { "prebootPath(\"\(path)\")" }
        static func prebootJailbreakPath(_ preboot: String, _ entry: String) -> String {
            "\(preboot)/\(entry)/\(jailbreakMarkerFile)"
        }
    }
    
    // MARK: - Private Properties
    private static let jailbreakListOptions = JailbreakListOptions()
    private static let logger = SecurityLogger.security(subsystem: Constants.loggerSubsystem)
    
    // MARK: - URL Scheme Checker
    private static let _urlSchemeChecker: ((URL) -> Bool)? = defaultURLSchemeChecker()

    private static func defaultURLSchemeChecker() -> ((URL) -> Bool)? {
#if !targetEnvironment(simulator)
        return { url in
            if Thread.isMainThread {
                return UIApplication.shared.canOpenURL(url)
            }
            var result = false
            DispatchQueue.main.sync {
                result = UIApplication.shared.canOpenURL(url)
            }
            return result
        }
#else
        return nil
#endif
    }
    
    // MARK: - Public
    
    public static func isJailbroken() -> Bool {
        return checkJailbreakFiles()
            || checkSandboxIntegrity()
            || checkForkCapability()
            || checkSuspiciousURLSchemes()
            || checkSymbolicLinks()
            || checkSuspiciousEnvironmentVars()
            || checkPrebootJailbreakPaths()
            || checkAntiDetectionToolLoadedImages()
    }
    
    public static func getDetectionDetails() -> [String] {
        var evidence: [String] = []
        evidence.append(contentsOf: collectFileEvidence())
        if checkSandboxIntegrity()  { evidence.append(Constants.evidenceSandboxEscape) }
        if checkForkCapability()    { evidence.append(Constants.evidenceForkSucceeded) }
        evidence.append(contentsOf: collectURLSchemeEvidence())
        evidence.append(contentsOf: collectSymlinkEvidence())
        evidence.append(contentsOf: collectEnvVarEvidence())
        evidence.append(contentsOf: collectPrebootEvidence())
        evidence.append(contentsOf: collectAntiDetectionToolEvidence())
        return evidence
    }

    // MARK: - Evidence Collectors

    private static func collectFileEvidence() -> [String] {
        var found: [String] = []
        for path in jailbreakListOptions.suspiciousPaths {
            if FileManager.default.fileExists(atPath: path) || FileManager.default.isReadableFile(atPath: path) {
                found.append(Constants.suspiciousPath(path))
            }
        }
        return found
    }

    private static func collectURLSchemeEvidence() -> [String] {
        guard let checker = _urlSchemeChecker else { return [] }
        var found: [String] = []
        for scheme in jailbreakListOptions.urlSchemes {
            if let url = URL(string: scheme), checker(url) {
                found.append(Constants.urlSchemeResponds(scheme))
            }
        }
        return found
    }

    private static func collectSymlinkEvidence() -> [String] {
        var found: [String] = []
        for path in jailbreakListOptions.suspiciousPaths {
            if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
               let fileType = attrs[.type] as? FileAttributeType,
               fileType == .typeSymbolicLink {
                found.append(Constants.symbolicLink(path))
            }
        }
        return found
    }

    private static func collectEnvVarEvidence() -> [String] {
#if DEBUG
        return []
#else
        var found: [String] = []
        for envVar in jailbreakListOptions.suspiciousVars {
            if isSuspiciousEnvVar(envVar) {
                found.append(Constants.envVarEvidence(envVar))
            }
        }
        return found
#endif
    }

    private static func collectAntiDetectionToolEvidence() -> [String] {
        var found: [String] = []
        let count = _dyld_image_count()
        for i in 0..<count {
            guard let rawName = _dyld_get_image_name(i) else { continue }
            let path = String(cString: rawName).lowercased()
            for marker in jailbreakListOptions.antiDetectionToolMarkers where path.contains(marker) {
                found.append(Constants.antiDetectionTool(path))
            }
        }
        return found
    }

    private static func collectPrebootEvidence() -> [String] {
        var found: [String] = []
        for path in jailbreakListOptions.suspiciousPaths {
            guard path.contains(Constants.prebootMarker) || path.contains(Constants.jailbreakRootMarker) else { continue }
            if FileManager.default.fileExists(atPath: path) {
                found.append(Constants.prebootPathEvidence(path))
            }
        }
        return found
    }

    private static func isSuspiciousEnvVar(_ name: String) -> Bool {
        guard let raw = getenv(name) else { return false }
        if name.hasPrefix(Constants.dyldPrefix) && SystemImageValidator.shared.isBenignDyldValue(String(cString: raw)) {
            return false
        }
        return true
    }

    // MARK: - Private Detection Methods
    
    private static func checkJailbreakFiles() -> Bool {
        for path in jailbreakListOptions.suspiciousPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
            
            if FileManager.default.isReadableFile(atPath: path) {
                return true
            }
        }
        
        return false
    }
    
    private static func checkSandboxIntegrity() -> Bool {
        for testPath in jailbreakListOptions.testPaths {
            do {
                try Constants.sandboxProbeContent.write(toFile: testPath, atomically: true, encoding: .utf8)
                try? FileManager.default.removeItem(atPath: testPath)
                return true
            } catch {
                continue
            }
        }
        
        return false
    }
    
    private static func checkSuspiciousURLSchemes() -> Bool {
        guard let checker = _urlSchemeChecker else {
            logger.debug(Constants.urlSchemeCheckSkipped)
            return false
        }
        
        for scheme in jailbreakListOptions.urlSchemes {
            if let url = URL(string: scheme), checker(url) {
                return true
            }
        }
        
        return false
    }
    
    private static func checkSymbolicLinks() -> Bool {
        for path in jailbreakListOptions.suspiciousPaths {
            do {
                let attributes = try FileManager.default.attributesOfItem(atPath: path)
                if let fileType = attributes[.type] as? FileAttributeType,
                   fileType == .typeSymbolicLink {
                    return true
                }
            } catch {
                continue
            }
        }
        
        return false
    }
    
    private static func checkSuspiciousEnvironmentVars() -> Bool {
#if DEBUG
        return false
#else
        for envVar in jailbreakListOptions.suspiciousVars {
            if isSuspiciousEnvVar(envVar) {
                return true
            }
        }
        return false
#endif
    }
    
    private static func checkForkCapability() -> Bool {
#if os(iOS) && !targetEnvironment(simulator)
        typealias ForkType = @convention(c) () -> pid_t

        guard let handle = dlopen(nil, RTLD_NOW) else { return false }
        defer { dlclose(handle) }
        guard let sym = dlsym(handle, Constants.forkSymbol) else { return false }

        let forkFn = unsafeBitCast(sym, to: ForkType.self)
        let pid = forkFn()

        if pid < 0 {
            return false
        }

        if pid == 0 {
            _exit(0)
        }

        var status: Int32 = 0
        waitpid(pid, &status, 0)
        return true
#else
        return false
#endif
    }
    
    private static let prebootPath = StringObfuscator.shared.reveal([0xA9, 0x23, 0x82, 0x28, 0x8C, 0x15, 0xC7, 0x4C, 0xBB, 0x96, 0x9A, 0xA2, 0x84, 0xDB, 0x6D, 0x57, 0x49, 0x28, 0xAC, 0x48])
    
    private static func checkPrebootJailbreakPaths() -> Bool {
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: prebootPath) else {
            return false
        }
        for entry in entries {
            let jbPath = Constants.prebootJailbreakPath(prebootPath, entry)
            if FileManager.default.fileExists(atPath: jbPath)
                || FileManager.default.isReadableFile(atPath: jbPath) {
                return true
            }
        }
        return false
    }

    private static func checkAntiDetectionToolLoadedImages() -> Bool {
        let count = _dyld_image_count()
        for i in 0..<count {
            guard let rawName = _dyld_get_image_name(i) else { continue }
            let path = String(cString: rawName).lowercased()
            for marker in jailbreakListOptions.antiDetectionToolMarkers where path.contains(marker) {
                logger.warning(Constants.antiDetectionTweakLog)
                return true
            }
        }
        return false
    }
}
