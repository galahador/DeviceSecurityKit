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
}
