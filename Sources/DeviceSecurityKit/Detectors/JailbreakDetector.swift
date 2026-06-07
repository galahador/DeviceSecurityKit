//
//  JailbreakDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
#if canImport(UIKit)
import UIKit
#endif
import Darwin

public final class JailbreakDetector {
    
    // MARK: - Private Properties
    private static let jailbreakListOptions = JailbreakListOptions()
    private static let logger = SecurityLogger.security(subsystem: "JailbreakDetector")
    
    // MARK: - URL Scheme Checker
    private static let _urlSchemeChecker: ((URL) -> Bool)? = defaultURLSchemeChecker()

    private static func defaultURLSchemeChecker() -> ((URL) -> Bool)? {
#if canImport(UIKit) && !targetEnvironment(simulator)
        return { url in
            // canOpenURL must be called on the main thread
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
    }
    
    public static func getDetectionDetails() -> [String] {
        var evidence: [String] = []
        evidence.append(contentsOf: collectFileEvidence())
        if checkSandboxIntegrity()  { evidence.append("sandboxEscapeWritable") }
        if checkForkCapability()    { evidence.append("forkSucceeded") }
        evidence.append(contentsOf: collectURLSchemeEvidence())
        evidence.append(contentsOf: collectSymlinkEvidence())
        evidence.append(contentsOf: collectEnvVarEvidence())
        evidence.append(contentsOf: collectPrebootEvidence())
        return evidence
    }

    // MARK: - Evidence Collectors

    private static func collectFileEvidence() -> [String] {
        var found: [String] = []
        for path in jailbreakListOptions.suspiciousPaths {
            if FileManager.default.fileExists(atPath: path) || FileManager.default.isReadableFile(atPath: path) {
                found.append("suspiciousPath(\"\(path)\")")
            }
        }
        return found
    }

    private static func collectURLSchemeEvidence() -> [String] {
        guard let checker = _urlSchemeChecker else { return [] }
        var found: [String] = []
        for scheme in jailbreakListOptions.urlSchemes {
            if let url = URL(string: scheme), checker(url) {
                found.append("urlSchemeResponds(\"\(scheme)\")")
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
                found.append("symbolicLink(\"\(path)\")")
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
            if getenv(envVar) != nil {
                found.append("envVar(\"\(envVar)\")")
            }
        }
        return found
#endif
    }

    private static func collectPrebootEvidence() -> [String] {
        var found: [String] = []
        for path in jailbreakListOptions.suspiciousPaths {
            guard path.contains("preboot") || path.contains("/var/jb") else { continue }
            if FileManager.default.fileExists(atPath: path) {
                found.append("prebootPath(\"\(path)\")")
            }
        }
        return found
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
                try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
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
            logger.debug("URL scheme check skipped — checker unavailable (simulator, or LSApplicationQueriesSchemes not configured in Info.plist)")
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
        // Xcode injects DYLD_INSERT_LIBRARIES (e.g. Main Thread Checker) in debug builds.
        return false
#else
        for envVar in jailbreakListOptions.suspiciousVars {
            if getenv(envVar) != nil {
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
        guard let sym = dlsym(handle, "fork") else { return false }

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
            let jbPath = "\(prebootPath)/\(entry)/jb"
            if FileManager.default.fileExists(atPath: jbPath)
                || FileManager.default.isReadableFile(atPath: jbPath) {
                return true
            }
        }
        return false
    }
}
