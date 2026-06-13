//
//  ExternalDisplayDetectorTests.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 13/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class ExternalDisplayDetectorTests: XCTestCase {

    // MARK: - Initial State

    func testIsExternalDisplayConnected_noExternalScreen_returnsFalse() {
        XCTAssertFalse(ExternalDisplayDetector.isExternalDisplayConnected())
    }

    func testCollectEvidence_noExternalScreen_isEmpty() {
        XCTAssertTrue(ExternalDisplayDetector.collectEvidence().isEmpty)
    }

    // MARK: - Observation Lifecycle

    func testStartStopObserving_doesNotCrash() {
        ExternalDisplayDetector.startObserving()
        ExternalDisplayDetector.startObserving() // safe to call multiple times
        ExternalDisplayDetector.stopObserving()
        ExternalDisplayDetector.stopObserving()
    }

    // MARK: - SecurityResult Integration

    func testSecurityResult_isExternalDisplayConnected() {
        let result = SecurityResult(threats: [.externalDisplayConnected])
        XCTAssertTrue(result.isExternalDisplayConnected)
        XCTAssertFalse(result.isSecure)
    }

    func testThreatSeverity_externalDisplayConnected_isMedium() {
        XCTAssertEqual(SecurityThreat.externalDisplayConnected.severity, .medium)
    }

    func testThreatIsPersistent_externalDisplayConnected_isFalse() {
        XCTAssertFalse(SecurityThreat.externalDisplayConnected.isPersistent)
    }
}
