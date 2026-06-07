//
//  ReverseEngineeringDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
import Darwin
import MachO

public final class ReverseEngineeringDetector {

    // MARK: - Private Properties
    private static let reverseEngineeringListsOptions = ReverseEngineeringListsOptions()
    private static let logger = SecurityLogger.security(subsystem: "ReverseEngineeringDetector")

    // MARK: - Public
    public static func isReverseEngineered() -> Bool {
        return checkSuspiciousLibraries()
            || checkEnvironmentVariables()
            || checkCodeIntegrity()
            || checkInstrumentationClasses()
    }
    
    // MARK: - Private
    private static func checkSuspiciousLibraries() -> Bool {
        for libraryName in reverseEngineeringListsOptions.suspiciousLibraries {
            if checkIfLibraryLoaded(libraryName) {
                return true
            }
        }
        
        return false
    }
    
    private static func checkIfLibraryLoaded(_ libraryName: String) -> Bool {
        let maxImages = _dyld_image_count()
        
        for i in 0..<maxImages {
            guard let imageName = _dyld_get_image_name(i) else { continue }
            let name = String(cString: imageName)
            
            if name.lowercased().contains(libraryName.lowercased()) {
                return true
            }
        }
        
        return false
    }
    
    private static func checkEnvironmentVariables() -> Bool {
#if DEBUG
        return false
#else
        for varName in reverseEngineeringListsOptions.suspiciousVars {
            if let value = getenv(varName), String(cString: value).count > 0 {
                return true
            }
        }
        return false
#endif
    }
    
    private static let validBundlePrefixes: [String] = {
        let o = StringObfuscator.shared
        return [
            o.reveal([0xBA, 0x9A, 0x79, 0x64, 0xC9, 0x0F, 0x6F, 0x63, 0x37, 0xD0, 0xBE, 0xE9, 0x30, 0x4B, 0x33, 0x3A, 0x1E, 0xAC, 0x11, 0x7B, 0x3F, 0xD9, 0x44, 0x1C, 0x14, 0x5E, 0x96, 0xBF, 0xF0, 0xCE, 0x70, 0x0C, 0x8C, 0x2A, 0xF7, 0x7B, 0x34, 0x63, 0xE5]),
            o.reveal([0xEA, 0x71, 0x07, 0x6B, 0x1D, 0xB7, 0xC6, 0x9A, 0x26, 0x34, 0x93, 0xE0, 0x95, 0x17, 0x54, 0x4F, 0x23, 0x6E, 0x8A, 0xD1, 0xD3, 0xF1, 0x6E, 0x55, 0xFC, 0x06, 0x91, 0x52, 0x23, 0x64, 0xB1, 0x3B, 0x37, 0xDE, 0x68, 0xFF, 0x74, 0xA0, 0x56, 0x50, 0xBF, 0x8B, 0xCF, 0x8A, 0x58, 0x52, 0xAA])
        ]
    }()
    
    // MARK: - Check: Instrumentation frameworks (FLEX, Reveal, DCIntrospect)

    private static func checkInstrumentationClasses() -> Bool {
#if !DEBUG
        let o = StringObfuscator.shared
        let suspiciousClassPrefixes = [
            o.reveal([0x45, 0x82, 0xF2, 0xD5, 0xBB, 0x3D, 0xC4, 0x19, 0xF2, 0x12, 0x3C, 0xD2, 0x90, 0xA7, 0x46]),
            o.reveal([0xB8, 0xE5, 0x90, 0x5D, 0x1E, 0xAC, 0x6D, 0x3C, 0x3F, 0x96, 0x0D, 0x6E, 0xD7, 0xD8, 0xB8, 0xF7]),
            o.reveal([0x69, 0xFF, 0x9C, 0x1C, 0x7A, 0xAD, 0xA4, 0x45, 0x58, 0x1F, 0x5F, 0xCC, 0x6F, 0x2A, 0xCE, 0x44, 0x4F, 0x68, 0x49]),
            o.reveal([0x6D, 0xD8, 0xCD, 0x96, 0xC4, 0x47, 0xBC, 0x5B, 0xF5, 0x3C, 0x3A, 0x81, 0x1C, 0x96, 0x10, 0xE5]),
            o.reveal([0x2D, 0x85, 0x73, 0x55, 0x44, 0x9B, 0x4F, 0xC6, 0x8E, 0x6C, 0xBE, 0x69, 0x2A, 0x22, 0xCF, 0xA6]),
        ]

        for prefix in suspiciousClassPrefixes {
            if NSClassFromString(prefix) != nil {
                logger.warning("Instrumentation class detected: \(SecurityLogger.redact(prefix))")
                return true
            }
        }
#endif
        return false
    }

    private static func checkCodeIntegrity() -> Bool {
        guard let executablePath = Bundle.main.executablePath else { return false }
        
        guard FileManager.default.fileExists(atPath: executablePath) else { return true }
        
#if os(iOS) && !targetEnvironment(simulator)
        let bundlePath = Bundle.main.bundlePath
        if !validBundlePrefixes.contains(where: { bundlePath.hasPrefix($0) }) {
            return true
        }
#endif
        
        return false
    }
}
