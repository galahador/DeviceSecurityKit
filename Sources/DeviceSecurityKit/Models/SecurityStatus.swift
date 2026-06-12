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
            return String(localized: "Device is secure", bundle: .module)
        case .jailbroken:
            return String(localized: "Device is jailbroken", bundle: .module)
        case .debuggerAttached:
            return String(localized: "Debugger is attached", bundle: .module)
        case .emulator:
            return String(localized: "Running in emulator", bundle: .module)
        case .reverseEngineered:
            return String(localized: "App has been tampered", bundle: .module)
        case .appIntegrityCompromised:
            return String(localized: "App signature integrity compromised", bundle: .module)
        case .screenRecording:
            return String(localized: "Screen is being recorded", bundle: .module)
        case .hooked:
            return String(localized: "Security functions have been hooked", bundle: .module)
        case .methodSwizzled:
            return String(localized: "Objective-C method swizzling detected", bundle: .module)
        case .pinningBypassed:
            return String(localized: "Certificate pinning has been bypassed", bundle: .module)
        case .vpnDetected:
            return String(localized: "VPN connection is active", bundle: .module)
        case .proxyDetected:
            return String(localized: "Proxy configuration is active", bundle: .module)
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
        case .compromised:
            return String(localized: "Device is compromised", bundle: .module)
        }
    }
}
