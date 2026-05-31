//
//  VPNProxyDetectorTests.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class VPNProxyDetectorTests: XCTestCase {

    // MARK: - SecurityThreat

    func testVPNThreatSeverity() {
        XCTAssertEqual(SecurityThreat.vpnDetected.severity, .medium)
    }

    func testProxyThreatSeverity() {
        XCTAssertEqual(SecurityThreat.proxyDetected.severity, .medium)
    }

    func testVPNDescription_nonEmpty() {
        XCTAssertFalse(SecurityThreat.vpnDetected.description.isEmpty)
    }

    func testProxyDescription_nonEmpty() {
        XCTAssertFalse(SecurityThreat.proxyDetected.description.isEmpty)
    }

    // MARK: - SecurityStatus

    func testVPNStatusDescription_nonEmpty() {
        XCTAssertFalse(SecurityStatus.vpnDetected.description.isEmpty)
        XCTAssertFalse(SecurityStatus.vpnDetected.isSecure)
    }

    func testProxyStatusDescription_nonEmpty() {
        XCTAssertFalse(SecurityStatus.proxyDetected.description.isEmpty)
        XCTAssertFalse(SecurityStatus.proxyDetected.isSecure)
    }

    // MARK: - SecurityResult

    func testIsVPNDetected_whenThreatPresent() {
        let result = SecurityResult(threats: [.vpnDetected])
        XCTAssertTrue(result.isVPNDetected)
        XCTAssertTrue(result.isVPNOrProxyActive)
        XCTAssertFalse(result.isProxyDetected)
        XCTAssertFalse(result.isSecure)
    }

    func testIsProxyDetected_whenThreatPresent() {
        let result = SecurityResult(threats: [.proxyDetected])
        XCTAssertTrue(result.isProxyDetected)
        XCTAssertTrue(result.isVPNOrProxyActive)
        XCTAssertFalse(result.isVPNDetected)
        XCTAssertFalse(result.isSecure)
    }

    func testIsVPNOrProxyActive_whenBothPresent() {
        let result = SecurityResult(threats: [.vpnDetected, .proxyDetected])
        XCTAssertTrue(result.isVPNOrProxyActive)
        XCTAssertTrue(result.isVPNDetected)
        XCTAssertTrue(result.isProxyDetected)
    }

    func testIsVPNOrProxyActive_whenThreatAbsent() {
        let result = SecurityResult(threats: [])
        XCTAssertFalse(result.isVPNOrProxyActive)
        XCTAssertFalse(result.isVPNDetected)
        XCTAssertFalse(result.isProxyDetected)
        XCTAssertTrue(result.isSecure)
    }

    // MARK: - DeviceSecurityConfiguration

    func testDefaultConfigHasVPNProxyEnabled() {
        XCTAssertTrue(DeviceSecurityConfiguration.default.vpnProxyDetectionEnabled)
    }

    func testWithVPNProxyDetection_disables() {
        let config = DeviceSecurityConfiguration.default.withVPNProxyDetection(false)
        XCTAssertFalse(config.vpnProxyDetectionEnabled)
    }

    func testWithVPNProxyDetection_enables() {
        let config = DeviceSecurityConfiguration.default
            .withVPNProxyDetection(false)
            .withVPNProxyDetection(true)
        XCTAssertTrue(config.vpnProxyDetectionEnabled)
    }

    // MARK: - Detector (smoke test)

    func testIsVPNOrProxyActive_returnsBoolean() {
        let _ = VPNProxyDetector.isVPNOrProxyActive()
    }

    func testIsVPNActive_returnsBoolean() {
        let _ = VPNProxyDetector.isVPNActive()
    }

    func testIsProxyActive_returnsBoolean() {
        let _ = VPNProxyDetector.isProxyActive()
    }
}
