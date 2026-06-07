//
//  RepackagingDetectorTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 07/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class RepackagingDetectorTests: XCTestCase {

    // MARK: - Simulator Baseline

    func testIsRepackaged_simulator_returnsFalse() {
        #if targetEnvironment(simulator)
        XCTAssertFalse(
            RepackagingDetector.isRepackaged(expectedCertificateHash: nil),
            "Simulator always returns false"
        )
        #endif
    }

    func testIsRepackaged_nilHash_returnsFalse() {
        // When no expected hash is provided, there's nothing to compare against
        XCTAssertFalse(RepackagingDetector.isRepackaged(expectedCertificateHash: nil))
    }

    func testIsRepackaged_emptyHash_returnsFalse() {
        XCTAssertFalse(RepackagingDetector.isRepackaged(expectedCertificateHash: ""))
    }

    func testCurrentCertificateHash_simulator() {
        #if targetEnvironment(simulator)
        // Simulator binaries may or may not have code signatures
        // Just verify it doesn't crash
        _ = RepackagingDetector.currentCertificateHash()
        #endif
    }

    // MARK: - SecurityResult Integration

    func testSecurityResult_isRepackaged() {
        let result = SecurityResult(threats: [.repackaged])
        XCTAssertTrue(result.isRepackaged)
        XCTAssertFalse(result.isSecure)
    }

    func testThreatSeverity_repackaged_isCritical() {
        XCTAssertEqual(SecurityThreat.repackaged.severity, .critical)
    }

    // MARK: - Monitor Integration

    func testMonitor_repackagingCheck_disabled() {
        let monitor = SecurityMonitor(
            configuration: .disabled
        )
        let result = monitor.performCheck()
        XCTAssertFalse(result.isRepackaged)
    }
}
