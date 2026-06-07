//
//  AttestationDetectorTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 07/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class AttestationDetectorTests: XCTestCase {

    override func tearDown() {
        super.tearDown()
        AttestationDetector.reset()
    }

    // MARK: - Initial State

    func testInitialState_notAttempted() {
        AttestationDetector.reset()
        XCTAssertFalse(AttestationDetector.hasAttempted)
        XCTAssertFalse(AttestationDetector.isAttestationFailed())
    }

    // MARK: - Mark Methods

    func testMarkAttestationSucceeded() {
        AttestationDetector.markAttestationSucceeded()
        XCTAssertTrue(AttestationDetector.hasAttempted)
        XCTAssertFalse(AttestationDetector.isAttestationFailed())
    }

    func testMarkAttestationFailed() {
        AttestationDetector.markAttestationFailed()
        XCTAssertTrue(AttestationDetector.hasAttempted)
        XCTAssertTrue(AttestationDetector.isAttestationFailed())
    }

    func testReset_clearsState() {
        AttestationDetector.markAttestationFailed()
        XCTAssertTrue(AttestationDetector.isAttestationFailed())

        AttestationDetector.reset()
        XCTAssertFalse(AttestationDetector.hasAttempted)
        XCTAssertFalse(AttestationDetector.isAttestationFailed())
    }

    // MARK: - SecurityResult Integration

    func testSecurityResult_isAttestationFailed() {
        let result = SecurityResult(threats: [.attestationFailed])
        XCTAssertTrue(result.isAttestationFailed)
        XCTAssertFalse(result.isSecure)
    }

    func testThreatSeverity_attestation_isCritical() {
        XCTAssertEqual(SecurityThreat.attestationFailed.severity, .critical)
    }

    // MARK: - Monitor Integration

    func testMonitor_attestationCheck_disabled() {
        let monitor = SecurityMonitor(
            configuration: .disabled.withAttestationCheck(false)
        )
        let result = monitor.performCheck()
        XCTAssertFalse(result.isAttestationFailed)
    }
}
