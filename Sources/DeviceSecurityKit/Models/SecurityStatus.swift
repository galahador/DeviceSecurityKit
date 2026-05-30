//
//  SecurityStatus.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

public enum SecurityStatus: Equatable {
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
    case vpnProxy
    case fridaDetected
    case attestationFailed
    case dskTampered
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
        case .vpnProxy:
            return "VPN or proxy connection is active"
        case .fridaDetected:
            return "Frida instrumentation runtime detected"
        case .attestationFailed:
            return "Device integrity attestation failed"
        case .dskTampered:
            return "Security library integrity compromised"
        case .compromised:
            return "Device is compromised"
        }
    }
}
