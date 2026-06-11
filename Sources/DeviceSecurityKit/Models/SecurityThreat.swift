//
//  SecurityThreat.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

public enum SecurityThreat: String, CaseIterable, Codable, Equatable, Sendable {
    case jailbreak
    case debugger
    case emulator
    case reverseEngineering
    case appIntegrity
    case screenRecording
    case hooked
    case pinningBypassed
    case vpnDetected
    case proxyDetected
    case methodSwizzling
    case fridaDetected
    case attestationFailed
    case dskTampered
    case repackaged
    case screenshotTaken
    case dylibInjection

    @available(*, deprecated, message: "Use an empty threats array instead of .noThreat")
    case noThreat

    public static var allCases: [SecurityThreat] {
        var cases: [SecurityThreat] = [
            .jailbreak, .debugger, .emulator, .reverseEngineering, .appIntegrity,
            .screenRecording, .hooked, .pinningBypassed, .vpnDetected, .proxyDetected,
            .methodSwizzling, .fridaDetected, .attestationFailed, .dskTampered,
            .repackaged, .screenshotTaken, .dylibInjection
        ]
        if let legacy = SecurityThreat(rawValue: "noThreat") {
            cases.append(legacy)
        }
        return cases
    }

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
        case .vpnDetected:
            return "VPN connection detected"
        case .proxyDetected:
            return "Proxy configuration detected"
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
        case .dylibInjection:
            return "Unauthorized dynamic library injected into process"
        case .noThreat:
            return "App is Secure"
        }
    }

    public var isPersistent: Bool {
        switch self {
        case .jailbreak, .debugger, .emulator, .reverseEngineering, .appIntegrity,
             .hooked, .pinningBypassed, .methodSwizzling, .fridaDetected,
             .attestationFailed, .dskTampered, .repackaged, .dylibInjection:
            return true
        case .screenRecording, .vpnDetected, .proxyDetected, .screenshotTaken, .noThreat:
            return false
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
        case .vpnDetected:
            return .medium
        case .proxyDetected:
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
        case .dylibInjection:
            return .critical
        case .noThreat:
            return .normal
        }
    }
}

public enum ThreatSeverity: Int, Codable, Comparable, Sendable, CustomStringConvertible {
    case normal = 0
    case low = 1
    case medium = 2
    case high = 3
    case critical = 4
    
    public static func < (lhs: ThreatSeverity, rhs: ThreatSeverity) -> Bool {
        return lhs.rawValue < rhs.rawValue
    }

    public var description: String {
        switch self {
        case .normal:   return "Normal"
        case .low:      return "Low"
        case .medium:   return "Medium"
        case .high:     return "High"
        case .critical: return "Critical"
        }
    }
}
