//
//  AppIntegrityDetectorTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 07/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class AppIntegrityDetectorTests: XCTestCase {

    // MARK: - Simulator Baseline

    func testIsIntegrityCompromised_simulator() {
        #if targetEnvironment(simulator)
        // All checks return false in simulator
        XCTAssertFalse(AppIntegrityDetector.isIntegrityCompromised())
        #endif
    }

    func testIsIntegrityCompromised_withTeamID_simulator() {
        #if targetEnvironment(simulator)
        XCTAssertFalse(
            AppIntegrityDetector.isIntegrityCompromised(expectedTeamID: "ABCDE12345"),
            "Simulator should not report integrity compromise"
        )
        #endif
    }

    // MARK: - SecurityResult Integration

    func testSecurityResult_isAppIntegrityCompromised() {
        let result = SecurityResult(threats: [.appIntegrity])
        XCTAssertTrue(result.isAppIntegrityCompromised)
        XCTAssertFalse(result.isSecure)
    }

    func testThreatSeverity_appIntegrity_isCritical() {
        XCTAssertEqual(SecurityThreat.appIntegrity.severity, .critical)
    }

    // MARK: - Monitor Integration

    func testMonitor_integrityCheck_disabled() {
        let monitor = SecurityMonitor(
            configuration: .disabled.withAppIntegrityCheck(false)
        )
        let result = monitor.performCheck()
        XCTAssertFalse(result.isAppIntegrityCompromised)
    }
}
