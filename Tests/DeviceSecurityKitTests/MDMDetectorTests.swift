//
//  MDMDetectorTests.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 13/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class MDMDetectorTests: XCTestCase {

    // MARK: - Baseline (no managed configuration in test host)

    func testIsManagedConfigurationPresent_noProfile_returnsFalse() {
        XCTAssertFalse(MDMDetector.isManagedConfigurationPresent())
    }

    func testCollectEvidence_noProfile_isEmpty() {
        XCTAssertTrue(MDMDetector.collectEvidence().isEmpty)
    }

    // MARK: - SecurityResult Integration

    func testSecurityResult_isMDMDetected() {
        let result = SecurityResult(threats: [.mdmDetected])
        XCTAssertTrue(result.isMDMDetected)
        XCTAssertFalse(result.isSecure)
    }

    func testThreatSeverity_mdmDetected_isLow() {
        XCTAssertEqual(SecurityThreat.mdmDetected.severity, .low)
    }

    func testThreatIsPersistent_mdmDetected_isFalse() {
        XCTAssertFalse(SecurityThreat.mdmDetected.isPersistent)
    }
}
