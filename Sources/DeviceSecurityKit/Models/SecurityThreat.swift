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
    case mdmDetected
    case clipboardExfiltration
    case externalDisplayConnected
    case thirdPartyKeyboardActive

    @available(*, deprecated, message: "Use an empty threats array instead of .noThreat")
    case noThreat

    public static var allCases: [SecurityThreat] {
        var cases: [SecurityThreat] = [
            .jailbreak, .debugger, .emulator, .reverseEngineering, .appIntegrity,
            .screenRecording, .hooked, .pinningBypassed, .vpnDetected, .proxyDetected,
            .methodSwizzling, .fridaDetected, .attestationFailed, .dskTampered,
            .repackaged, .screenshotTaken, .dylibInjection, .mdmDetected, .clipboardExfiltration,
            .externalDisplayConnected, .thirdPartyKeyboardActive
        ]
        if let legacy = SecurityThreat(rawValue: "noThreat") {
            cases.append(legacy)
        }
        return cases
    }

    public var description: String {
        switch self {
        case .jailbreak:
            return String(localized: "Device is jailbroken", bundle: .module)
        case .debugger:
            return String(localized: "Debugger attached", bundle: .module)
        case .emulator:
            return String(localized: "Running in emulator", bundle: .module)
        case .reverseEngineering:
            return String(localized: "App tampering detected", bundle: .module)
        case .appIntegrity:
            return String(localized: "App signature integrity compromised", bundle: .module)
        case .screenRecording:
            return String(localized: "Screen is being recorded", bundle: .module)
        case .hooked:
            return String(localized: "Security functions have been hooked", bundle: .module)
        case .pinningBypassed:
            return String(localized: "Certificate pinning bypass detected", bundle: .module)
        case .vpnDetected:
            return String(localized: "VPN connection detected", bundle: .module)
        case .proxyDetected:
            return String(localized: "Proxy configuration detected", bundle: .module)
        case .methodSwizzling:
            return String(localized: "Objective-C method swizzling detected", bundle: .module)
        case .fridaDetected:
            return String(localized: "Frida instrumentation runtime detected", bundle: .module)
        case .attestationFailed:
            return String(localized: "Device integrity attestation failed", bundle: .module)
        case .dskTampered:
            return String(localized: "Security library integrity compromised", bundle: .module)
        case .repackaged:
            return String(localized: "App has been resigned with a different certificate", bundle: .module)
        case .screenshotTaken:
            return String(localized: "User took a screenshot of the app", bundle: .module)
        case .dylibInjection:
            return String(localized: "Unauthorized dynamic library injected into process", bundle: .module)
        case .mdmDetected:
            return String(localized: "Device is under MDM/enterprise management", bundle: .module)
        case .clipboardExfiltration:
            return String(localized: "Clipboard contents changed unexpectedly after a sensitive copy", bundle: .module)
        case .externalDisplayConnected:
            return String(localized: "An external display is connected — possible screen mirroring", bundle: .module)
        case .thirdPartyKeyboardActive:
            return String(localized: "A third-party keyboard is active on a sensitive field", bundle: .module)
        case .noThreat:
            return String(localized: "App is Secure", bundle: .module)
        }
    }

    public var isPersistent: Bool {
        switch self {
        case .jailbreak, .debugger, .emulator, .reverseEngineering, .appIntegrity,
             .hooked, .pinningBypassed, .methodSwizzling, .fridaDetected,
             .attestationFailed, .dskTampered, .repackaged, .dylibInjection:
            return true
        case .screenRecording, .vpnDetected, .proxyDetected, .screenshotTaken, .mdmDetected,
             .clipboardExfiltration, .externalDisplayConnected, .thirdPartyKeyboardActive, .noThreat:
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
        case .mdmDetected:
            return .low
        case .clipboardExfiltration:
            return .medium
        case .externalDisplayConnected:
            return .medium
        case .thirdPartyKeyboardActive:
            return .medium
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
        case .normal:   return String(localized: "Normal", bundle: .module)
        case .low:      return String(localized: "Low", bundle: .module)
        case .medium:   return String(localized: "Medium", bundle: .module)
        case .high:     return String(localized: "High", bundle: .module)
        case .critical: return String(localized: "Critical", bundle: .module)
        }
    }
}
