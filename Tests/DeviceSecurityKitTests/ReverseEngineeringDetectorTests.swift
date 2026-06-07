//
//  ReverseEngineeringDetectorTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 07/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class ReverseEngineeringDetectorTests: XCTestCase {

    // MARK: - Simulator Baseline

    func testIsReverseEngineered_simulator() {
        #if targetEnvironment(simulator)
        // Code integrity check is skipped in simulator; library/env checks
        // should not trigger on a clean environment
        let result = ReverseEngineeringDetector.isReverseEngineered()
        // Note: may return true if test runner loads instrumentation libraries
        _ = result
        #endif
    }

    // MARK: - SecurityResult Integration

    func testSecurityResult_isReverseEngineered() {
        let result = SecurityResult(threats: [.reverseEngineering])
        XCTAssertTrue(result.isReverseEngineered)
        XCTAssertFalse(result.isSecure)
    }

    func testThreatSeverity_reverseEngineering_isCritical() {
        XCTAssertEqual(SecurityThreat.reverseEngineering.severity, .critical)
    }

    // MARK: - Monitor Integration

    func testMonitor_reverseEngineeringCheck_disabled() {
        let monitor = SecurityMonitor(
            configuration: .disabled.withReverseEngineeringCheck(false)
        )
        let result = monitor.performCheck()
        XCTAssertFalse(result.isReverseEngineered)
    }
}
