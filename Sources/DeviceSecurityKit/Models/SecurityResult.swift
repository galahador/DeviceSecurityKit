//
//  SecurityResult.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

public struct SecurityResult: Equatable {
    public let threats: [SecurityThreat]
    public let evidence: [SecurityThreat: [String]]

    public init(threats: [SecurityThreat] = [], evidence: [SecurityThreat: [String]] = [:]) {
        self.threats = threats
        self.evidence = evidence
    }

    /// Returns the evidence strings for a specific threat, or empty if none.
    public func evidence(for threat: SecurityThreat) -> [String] {
        return evidence[threat] ?? []
    }
    
    public var isSecure: Bool {
        return threats.isEmpty || !threats.contains(where: { $0 != .noThreat })
    }
    
    public var isJailbroken: Bool {
        return threats.contains(.jailbreak)
    }
    
    public var isDebuggerAttached: Bool {
        return threats.contains(.debugger)
    }
    
    public var isEmulator: Bool {
        return threats.contains(.emulator)
    }
    
    public var isReverseEngineered: Bool {
        return threats.contains(.reverseEngineering)
    }

    public var isScreenRecorded: Bool {
        return threats.contains(.screenRecording)
    }

    public var isFunctionHooked: Bool {
        return threats.contains(.hooked)
    }

    public var isPinningBypassed: Bool {
        return threats.contains(.pinningBypassed)
    }

    public var isVPNDetected: Bool {
        return threats.contains(.vpnDetected)
    }

    public var isProxyDetected: Bool {
        return threats.contains(.proxyDetected)
    }

    public var isVPNOrProxyActive: Bool {
        return isVPNDetected || isProxyDetected
    }

    public var isAppIntegrityCompromised: Bool {
        return threats.contains(.appIntegrity)
    }

    public var isMethodSwizzled: Bool {
        return threats.contains(.methodSwizzling)
    }

    public var isFridaDetected: Bool {
        return threats.contains(.fridaDetected)
    }

    public var isAttestationFailed: Bool {
        return threats.contains(.attestationFailed)
    }

    public var isDSKTampered: Bool {
        return threats.contains(.dskTampered)
    }

    public var isRepackaged: Bool {
        return threats.contains(.repackaged)
    }

    public var isScreenshotTaken: Bool {
        return threats.contains(.screenshotTaken)
    }

    public var isDylibInjected: Bool {
        return threats.contains(.dylibInjection)
    }

    public static let secure = SecurityResult(threats: [])
}
