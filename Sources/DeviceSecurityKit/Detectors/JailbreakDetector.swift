//
//  JailbreakDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
import Darwin

public final class JailbreakDetector {
    
    // MARK: - Private Properties
    private static let jailbreakListOptions = JailbreakListOptions()
    private static let detectionQueue = DispatchQueue(label: "JailbreakDetector.detection", attributes: .concurrent)
    
    // MARK: - Master Switch
    
    private static var _isDetectionEnabled: Bool = true
    
    internal static var isDetectionEnabled: Bool {
        get { detectionQueue.sync { _isDetectionEnabled } }
        set { detectionQueue.sync(flags: .barrier) { _isDetectionEnabled = newValue } }
    }
    
    // MARK: - Per-Check Switches
    
    private static var _isFileCheckEnabled: Bool = true
    private static var _isSandboxCheckEnabled: Bool = true
    private static var _isForkCheckEnabled: Bool = true
    private static var _isURLSchemeCheckEnabled: Bool = true
    private static var _isSymbolicLinkCheckEnabled: Bool = true
    private static var _isEnvironmentVarCheckEnabled: Bool = true
    private static var _isPrebootCheckEnabled: Bool = true
    
    public static var isFileCheckEnabled: Bool {
        get { detectionQueue.sync { _isFileCheckEnabled } }
        set { detectionQueue.sync(flags: .barrier) { _isFileCheckEnabled = newValue } }
    }
    
    public static var isSandboxCheckEnabled: Bool {
        get { detectionQueue.sync { _isSandboxCheckEnabled } }
        set { detectionQueue.sync(flags: .barrier) { _isSandboxCheckEnabled = newValue } }
    }
    
    public static var isForkCheckEnabled: Bool {
        get { detectionQueue.sync { _isForkCheckEnabled } }
        set { detectionQueue.sync(flags: .barrier) { _isForkCheckEnabled = newValue } }
    }
    
    public static var isURLSchemeCheckEnabled: Bool {
        get { detectionQueue.sync { _isURLSchemeCheckEnabled } }
        set { detectionQueue.sync(flags: .barrier) { _isURLSchemeCheckEnabled = newValue } }
    }
    
    public static var isSymbolicLinkCheckEnabled: Bool {
        get { detectionQueue.sync { _isSymbolicLinkCheckEnabled } }
        set { detectionQueue.sync(flags: .barrier) { _isSymbolicLinkCheckEnabled = newValue } }
    }
    
    public static var isEnvironmentVarCheckEnabled: Bool {
        get { detectionQueue.sync { _isEnvironmentVarCheckEnabled } }
        set { detectionQueue.sync(flags: .barrier) { _isEnvironmentVarCheckEnabled = newValue } }
    }
    
    public static var isPrebootCheckEnabled: Bool {
        get { detectionQueue.sync { _isPrebootCheckEnabled } }
        set { detectionQueue.sync(flags: .barrier) { _isPrebootCheckEnabled = newValue } }
    }
    
    // MARK: - URL Scheme Checker
    private static var _urlSchemeChecker: ((URL) -> Bool)?
    public static var urlSchemeChecker: ((URL) -> Bool)? {
        get { detectionQueue.sync { _urlSchemeChecker } }
        set { detectionQueue.sync(flags: .barrier) { _urlSchemeChecker = newValue } }
    }
    
    // MARK: - Public
    
    public static func isJailbroken() -> Bool {
        guard isDetectionEnabled else { return false }
        
        let (file, sandbox, fork, url, symlink, env, preboot) = detectionQueue.sync {
            (_isFileCheckEnabled, _isSandboxCheckEnabled, _isForkCheckEnabled,
             _isURLSchemeCheckEnabled, _isSymbolicLinkCheckEnabled,
             _isEnvironmentVarCheckEnabled, _isPrebootCheckEnabled)
        }
        
        return (file     && checkJailbreakFiles())
        || (sandbox  && checkSandboxIntegrity())
        || (fork     && checkForkCapability())
        || (url      && checkSuspiciousURLSchemes())
        || (symlink  && checkSymbolicLinks())
        || (env      && checkSuspiciousEnvironmentVars())
        || (preboot  && checkPrebootJailbreakPaths())
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
        guard let checker = detectionQueue.sync(execute: { _urlSchemeChecker }) else { return false }
        
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
        if pid == 0 {
            exit(0)
        }
        return pid > 0
#else
        return false
#endif
    }
    
    private static let prebootPath = StringObfuscator.shared.reveal(
        [0x85, 0xDA, 0xD8, 0xC3, 0xDC, 0xCB, 0xDE, 0xCF, 0x85, 0xDA, 0xD8, 0xCF, 0xC8, 0xC5, 0xC5, 0xDE]
    )
    
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
