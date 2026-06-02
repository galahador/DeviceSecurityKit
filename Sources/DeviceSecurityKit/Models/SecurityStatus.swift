//
//  SecurityStatus.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

public enum SecurityStatus: Equatable, Sendable {
    case secure
    case jailbroken
    case debuggerAttached
    case emulator
    case reverseEngineered
    case appIntegrityCompromised
    case screenRecording
    case hooked
    case methodSwizzled
    case pinningBypassed
    case vpnDetected
    case proxyDetected
    case fridaDetected
    case attestationFailed
    case dskTampered
    case repackaged
    case screenshotTaken
    case dylibInjection
    case compromised

    public var isSecure: Bool {
        return self == .secure
    }

    public var description: String {
        switch self {
        case .secure:
            return "Device is secure"
        case .jailbroken:
            return "Device is jailbroken"
        case .debuggerAttached:
            return "Debugger is attached"
        case .emulator:
            return "Running in emulator"
        case .reverseEngineered:
            return "App has been tampered"
        case .appIntegrityCompromised:
            return "App signature integrity compromised"
        case .screenRecording:
            return "Screen is being recorded"
        case .hooked:
            return "Security functions have been hooked"
        case .methodSwizzled:
            return "Objective-C method swizzling detected"
        case .pinningBypassed:
            return "Certificate pinning has been bypassed"
        case .vpnDetected:
            return "VPN connection is active"
        case .proxyDetected:
            return "Proxy configuration is active"
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
        case .compromised:
            return "Device is compromised"
        }
    }
}
