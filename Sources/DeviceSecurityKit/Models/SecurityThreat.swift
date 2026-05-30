//
//  SecurityThreat.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

public enum SecurityThreat: String, CaseIterable, Equatable {
    case jailbreak
    case debugger
    case emulator
    case reverseEngineering
    case appIntegrity
    case screenRecording
    case hooked
    case pinningBypassed
    case vpnProxy
    case methodSwizzling
    case fridaDetected
    case attestationFailed
    case dskTampered
    case repackaged
    case screenshotTaken
    case noThreat

    public var description: String {
        switch self {
        case .jailbreak:
            return "Device is jailbroken"
        case .debugger:
            return "Debugger attached"
        case .emulator:
            return "Running in emulator"
        case .reverseEngineering:
            return "App tampering detected"
        case .appIntegrity:
            return "App signature integrity compromised"
        case .screenRecording:
            return "Screen is being recorded"
        case .hooked:
            return "Security functions have been hooked"
        case .pinningBypassed:
            return "Certificate pinning bypass detected"
        case .vpnProxy:
            return "VPN or proxy connection detected"
        case .methodSwizzling:
            return "Objective-C method swizzling detected"
        case .fridaDetected:
            return "Frida instrumentation runtime detected"
        case .attestationFailed:
            return "Device integrity attestation failed"
        case .dskTampered:
            return "Security library integrity compromised"
        case .repackaged:
            return "App has been resigned with a different certificate"
        case .screenshotTaken:
            return "User took a screenshot of the app"
        case .noThreat:
            return "App is Secure"
        }
    }

    public var severity: ThreatSeverity {
        switch self {
        case .jailbreak:
            return .critical
        case .reverseEngineering:
            return .critical
        case .appIntegrity:
            return .critical
        case .hooked:
            return .critical
        case .pinningBypassed:
            return .critical
        case .debugger:
            return .high
        case .screenRecording:
            return .high
        case .emulator:
            return .medium
        case .vpnProxy:
            return .medium
        case .methodSwizzling:
            return .critical
        case .fridaDetected:
            return .critical
        case .attestationFailed:
            return .critical
        case .dskTampered:
            return .critical
        case .repackaged:
            return .critical
        case .screenshotTaken:
            return .medium
        case .noThreat:
            return .normal
        }
    }
}

public enum ThreatSeverity: Int, Comparable {
    case normal = 0
    case low = 1
    case medium = 2
    case high = 3
    case critical = 4
    
    public static func < (lhs: ThreatSeverity, rhs: ThreatSeverity) -> Bool {
        return lhs.rawValue < rhs.rawValue
    }
}
