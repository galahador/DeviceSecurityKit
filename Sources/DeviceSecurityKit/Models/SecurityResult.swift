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
        return threats.isEmpty
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

    public var isMDMDetected: Bool {
        return threats.contains(.mdmDetected)
    }

    public var isClipboardExfiltration: Bool {
        return threats.contains(.clipboardExfiltration)
    }

    public var isExternalDisplayConnected: Bool {
        return threats.contains(.externalDisplayConnected)
    }

    public var isThirdPartyKeyboardActive: Bool {
        return threats.contains(.thirdPartyKeyboardActive)
    }

    // MARK: - Threat Queries

    /// Returns threats matching the given severity level.
    public func threats(bySeverity severity: ThreatSeverity) -> [SecurityThreat] {
        return threats.filter { $0.severity == severity }
    }

    /// Number of critical-severity threats in this result.
    public var criticalThreatCount: Int {
        return threats.count { $0.severity == .critical }
    }

    // MARK: - Risk Score

    /// Composite risk score in `[0.0, 1.0]` derived from active threats.
    public var riskScore: Double {
        let active = threats
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

    // MARK: - Report

    public func generateReport(generatedAt: Date = Date()) -> String {
        let formatter = ISO8601DateFormatter()
        let statusText = isSecure
            ? String(localized: "Secure", bundle: .module)
            : String(localized: "Compromised", bundle: .module)
        var lines: [String] = []
        lines.append(String(localized: "DeviceSecurityKit Security Report", bundle: .module))
        lines.append("\(String(localized: "Generated:", bundle: .module)) \(formatter.string(from: generatedAt))")
        lines.append("\(String(localized: "Status:", bundle: .module)) \(statusText)")
        lines.append("\(String(localized: "Risk Score:", bundle: .module)) \(String(format: "%.2f", riskScore)) (\(riskLevel))")
        lines.append("\(String(localized: "Threats Detected:", bundle: .module)) \(threats.count)")

        if threats.isEmpty {
            lines.append(String(localized: "No threats detected.", bundle: .module))
        } else {
            for threat in threats.sorted(by: { $0.severity > $1.severity }) {
                lines.append("- [\(threat.severity)] \(threat.rawValue): \(threat.description)")
                for item in evidence(for: threat) {
                    lines.append("    • \(item)")
                }
            }
        }

        return lines.joined(separator: "\n")
    }
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
        case .none:     return String(localized: "None", bundle: .module)
        case .low:      return String(localized: "Low", bundle: .module)
        case .medium:   return String(localized: "Medium", bundle: .module)
        case .high:     return String(localized: "High", bundle: .module)
        case .critical: return String(localized: "Critical", bundle: .module)
        }
    }
}
