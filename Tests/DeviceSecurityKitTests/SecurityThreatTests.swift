//
//  SecurityThreatTests.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class SecurityThreatTests: XCTestCase {

    func testSeverityLevels() {
        XCTAssertEqual(SecurityThreat.jailbreak.severity, .critical)
        XCTAssertEqual(SecurityThreat.reverseEngineering.severity, .critical)
        XCTAssertEqual(SecurityThreat.hooked.severity, .critical)
        XCTAssertEqual(SecurityThreat.pinningBypassed.severity, .critical)
        XCTAssertEqual(SecurityThreat.debugger.severity, .high)
        XCTAssertEqual(SecurityThreat.screenRecording.severity, .high)
        XCTAssertEqual(SecurityThreat.emulator.severity, .medium)
        XCTAssertEqual(SecurityThreat.noThreat.severity, .normal)
    }

    func testSeverityComparison() {
        XCTAssertLessThan(ThreatSeverity.normal, .low)
        XCTAssertLessThan(ThreatSeverity.low, .medium)
        XCTAssertLessThan(ThreatSeverity.medium, .high)
        XCTAssertLessThan(ThreatSeverity.high, .critical)
        XCTAssertGreaterThan(ThreatSeverity.critical, .normal)
        XCTAssertEqual(SecurityThreat.emulator.severity, .medium)
    }

    func testDescriptions_nonEmpty() {
        for threat in SecurityThreat.allCases {
            XCTAssertFalse(threat.description.isEmpty, "Missing description for \(threat)")
        }
    }

    func testHashable() {
        let set: Set<SecurityThreat> = [.jailbreak, .jailbreak, .debugger, .screenRecording, .hooked]
        XCTAssertEqual(set.count, 4)
    }

    func testAllCasesCount() {
        XCTAssertEqual(SecurityThreat.allCases.count, 18)
        let set: Set<SecurityThreat> = [.jailbreak, .jailbreak, .debugger, .screenRecording]
        XCTAssertEqual(set.count, 3)
    }

    // MARK: - Risk Score

    func testRiskScore_noThreats() {
        let result = SecurityResult(threats: [])
        XCTAssertEqual(result.riskScore, 0.0)
        XCTAssertEqual(result.riskLevel, .none)
    }

    func testRiskScore_noThreatOnly() {
        let result = SecurityResult(threats: [.noThreat])
        XCTAssertEqual(result.riskScore, 0.0)
        XCTAssertEqual(result.riskLevel, .none)
    }

    func testRiskScore_singleMedium() {
        let result = SecurityResult(threats: [.emulator])
        XCTAssertGreaterThan(result.riskScore, 0.2)
        XCTAssertLessThan(result.riskScore, 0.5)
        XCTAssertEqual(result.riskLevel, .medium)
    }

    func testRiskScore_singleCritical() {
        let result = SecurityResult(threats: [.jailbreak])
        XCTAssertGreaterThan(result.riskScore, 0.7)
        XCTAssertLessThanOrEqual(result.riskScore, 1.0)
        XCTAssertEqual(result.riskLevel, .critical)
    }

    func testRiskScore_multipleCritical() {
        let result = SecurityResult(threats: [.jailbreak, .fridaDetected, .hooked])
        XCTAssertGreaterThan(result.riskScore, 0.8)
        XCTAssertEqual(result.riskLevel, .critical)
    }

    func testRiskScore_escalatesWithMoreThreats() {
        let single = SecurityResult(threats: [.jailbreak])
        let double = SecurityResult(threats: [.jailbreak, .fridaDetected])
        let triple = SecurityResult(threats: [.jailbreak, .fridaDetected, .hooked])
        XCTAssertLessThan(single.riskScore, double.riskScore)
        XCTAssertLessThan(double.riskScore, triple.riskScore)
    }

    func testRiskScore_cappedAtOne() {
        let result = SecurityResult(threats: [
            .jailbreak, .fridaDetected, .hooked, .reverseEngineering,
            .appIntegrity, .methodSwizzling, .dylibInjection, .repackaged
        ])
        XCTAssertLessThanOrEqual(result.riskScore, 1.0)
        XCTAssertEqual(result.riskLevel, .critical)
    }

    func testRiskLevel_comparable() {
        XCTAssertLessThan(RiskLevel.none, .low)
        XCTAssertLessThan(RiskLevel.low, .medium)
        XCTAssertLessThan(RiskLevel.medium, .high)
        XCTAssertLessThan(RiskLevel.high, .critical)
    }

    func testRiskLevel_descriptions() {
        for level in [RiskLevel.none, .low, .medium, .high, .critical] {
            XCTAssertFalse(level.description.isEmpty)
        }
    }
}
