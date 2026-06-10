//
//  SwizzlingDetectorTests.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class SwizzlingDetectorTests: XCTestCase {

    // MARK: - Detector

    func testIsSwizzled_cleanEnvironment_returnsFalse() {
        XCTAssertFalse(SwizzlingDetector.isSwizzled())
    }

    func testNoThreat_whenCheckDisabled() {
        let monitor = SecurityMonitor(configuration: .disabled.withSwizzlingDetection(false))
        let result = monitor.performCheck()
        XCTAssertFalse(result.isMethodSwizzled)
    }

    func testSecurityResult_isMethodSwizzled() {
        let result = SecurityResult(threats: [.methodSwizzling])
        XCTAssertTrue(result.isMethodSwizzled)
        XCTAssertFalse(result.isJailbroken)
        XCTAssertFalse(result.isFunctionHooked)
    }

    func testSecurityResult_noSwizzling() {
        let result = SecurityResult(threats: [])
        XCTAssertFalse(result.isMethodSwizzled)
        XCTAssertTrue(result.isSecure)
    }

    func testThreatSeverity_isCorrect() {
        XCTAssertEqual(SecurityThreat.methodSwizzling.severity, .critical)
    }

    func testThreatDescription_nonEmpty() {
        XCTAssertFalse(SecurityThreat.methodSwizzling.description.isEmpty)
    }

    func testConfiguration_swizzlingEnabledByDefault() {
        let config = DeviceSecurityConfiguration()
        XCTAssertTrue(config.swizzlingDetectionEnabled)
    }

    func testConfiguration_builderDisables() {
        let config = DeviceSecurityConfiguration().withSwizzlingDetection(false)
        XCTAssertFalse(config.swizzlingDetectionEnabled)
    }

    func testAllCasesContainsMethodSwizzling() {
        XCTAssertTrue(SecurityThreat.allCases.contains(.methodSwizzling))
    }

    func testStatusDescription_methodSwizzled() {
        XCTAssertFalse(SecurityStatus.methodSwizzled.description.isEmpty)
        XCTAssertFalse(SecurityStatus.methodSwizzled.isSecure)
    }
}
