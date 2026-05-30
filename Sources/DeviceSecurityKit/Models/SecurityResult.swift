//
//  SecurityResult.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

public struct SecurityResult: Equatable {
    public let threats: [SecurityThreat]
    
    public init(threats: [SecurityThreat] = []) {
        self.threats = threats
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

    public var isVPNOrProxyActive: Bool {
        return threats.contains(.vpnProxy)
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

    public static let secure = SecurityResult(threats: [])
}
