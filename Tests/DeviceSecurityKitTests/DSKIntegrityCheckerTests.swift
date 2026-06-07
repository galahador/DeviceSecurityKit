//
//  DSKIntegrityCheckerTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 07/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class DSKIntegrityCheckerTests: XCTestCase {

    // MARK: - Simulator Baseline

    func testIsDSKCompromised_simulator() {
        #if targetEnvironment(simulator)
        // Both IMP check and text checksum are disabled on simulator
        XCTAssertFalse(DSKIntegrityChecker.isDSKCompromised())
        #endif
    }

    func testCaptureBaseline_doesNotCrash() {
        // Just verify it can be called without crashing
        DSKIntegrityChecker.captureBaseline()
    }

    // MARK: - SecurityResult Integration

    func testSecurityResult_isDSKTampered() {
        let result = SecurityResult(threats: [.dskTampered])
        XCTAssertTrue(result.isDSKTampered)
        XCTAssertFalse(result.isSecure)
    }

    func testThreatSeverity_dskTampered_isCritical() {
        XCTAssertEqual(SecurityThreat.dskTampered.severity, .critical)
    }
}
