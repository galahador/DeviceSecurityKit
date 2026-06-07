//
//  SecurityResult.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

public struct SecurityResult: Equatable, Codable, Sendable {
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

    // MARK: - Risk Score

    /// Composite risk score in `[0.0, 1.0]` derived from active threats.
    ///
    /// The score has two components:
    ///
    /// 1. **Floor** — maps the single highest severity to a `0–0.7` range:
    ///    `floor = maxSeverity / critical.rawValue × 0.7`
    ///
    /// 2. **Compound bonus** — rewards multiple threats via a log curve that
    ///    grows slowly, preventing any combination from overshooting 1.0:
    ///    `bonus = min(log₂(1 + totalWeight) / 15, 0.3)`
    ///
    /// The final score is `min(floor + bonus, 1.0)`.
    ///
    /// | Scenario                     | Approximate score |
    /// |------------------------------|-------------------|
    /// | No threats                   | 0.0               |
    /// | One medium threat            | ~0.35             |
    /// | One critical threat          | ~0.70             |
    /// | Two critical threats         | ~0.82             |
    /// | Three+ critical threats      | 0.90 – 1.0       |
    public var riskScore: Double {
        let active = threats.filter { $0 != .noThreat }
        guard !active.isEmpty else { return 0.0 }

        let maxSeverity = active.map { $0.severity.rawValue }.max() ?? 0
        let totalWeight = active.reduce(0) { $0 + $1.severity.rawValue }

        // Floor: highest severity mapped to 0–0.7 range
        let floor = Double(maxSeverity) / Double(ThreatSeverity.critical.rawValue) * 0.7

        // Compound bonus: sum of all severity weights, diminishing via log curve
        // log2(1 + totalWeight) grows slowly — 4→2.3, 8→3.2, 12→3.7, 20→4.4
        let compoundBonus = min(log2(1.0 + Double(totalWeight)) / 15.0, 0.3)

        return min(floor + compoundBonus, 1.0)
    }

    /// Human-readable risk level derived from `riskScore`.
    public var riskLevel: RiskLevel {
        switch riskScore {
        case 0.0:
            return .none
        case ..<0.25:
            return .low
        case ..<0.50:
            return .medium
        case ..<0.75:
            return .high
        default:
            return .critical
        }
    }

    public static let secure = SecurityResult(threats: [])
}

// MARK: - Risk Level

public enum RiskLevel: Int, Codable, Comparable, CustomStringConvertible {
    case none = 0
    case low = 1
    case medium = 2
    case high = 3
    case critical = 4

    public static func < (lhs: RiskLevel, rhs: RiskLevel) -> Bool {
        return lhs.rawValue < rhs.rawValue
    }

    public var description: String {
        switch self {
        case .none:     return "None"
        case .low:      return "Low"
        case .medium:   return "Medium"
        case .high:     return "High"
        case .critical: return "Critical"
        }
    }
}
