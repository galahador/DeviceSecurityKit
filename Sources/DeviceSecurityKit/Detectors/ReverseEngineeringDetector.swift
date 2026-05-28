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
    private static var reverseEngineeringListsOptions = ReverseEngineeringListsOptions()
    
    // MARK: - Public
    public static func isReverseEngineered() -> Bool {
        return checkSuspiciousLibraries()
        || checkEnvironmentVariables()
        || checkCodeIntegrity()
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
