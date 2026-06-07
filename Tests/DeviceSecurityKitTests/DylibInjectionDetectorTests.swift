//
//  DylibInjectionDetectorTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 07/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class DylibInjectionDetectorTests: XCTestCase {

    // MARK: - Simulator Baseline

    func testIsDylibInjected_simulator() {
        #if targetEnvironment(simulator)
        XCTAssertFalse(DylibInjectionDetector.isDylibInjected(), "Simulator returns false by design")
        #endif
    }

    func testCollectEvidence_simulator_isEmpty() {
        #if targetEnvironment(simulator)
        let evidence = DylibInjectionDetector.collectEvidence()
        XCTAssertTrue(evidence.isEmpty, "Simulator returns empty evidence by design")
        #endif
    }

    // MARK: - SecurityResult Integration

    func testSecurityResult_isDylibInjected() {
        let result = SecurityResult(threats: [.dylibInjection])
        XCTAssertTrue(result.isDylibInjected)
        XCTAssertFalse(result.isSecure)
    }

    func testThreatSeverity_dylibInjection_isCritical() {
        XCTAssertEqual(SecurityThreat.dylibInjection.severity, .critical)
    }

    // MARK: - Monitor Integration

    func testMonitor_dylibCheck_disabled() {
        let monitor = SecurityMonitor(
            configuration: .disabled
        )
        let result = monitor.performCheck()
        XCTAssertFalse(result.isDylibInjected)
    }
}
