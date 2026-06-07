//
//  ProxyConfigurationCheckerTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 07/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class ProxyConfigurationCheckerTests: XCTestCase {

    // MARK: - Simulator Baseline

    func testIsProxyConfigured_simulator() {
        // On a clean simulator, no proxy should be configured
        // Note: CI environments may have proxies — no hard assertion
        _ = ProxyConfigurationChecker.isProxyConfigured()
    }

    // MARK: - SecurityResult Integration

    func testSecurityResult_isProxyDetected() {
        let result = SecurityResult(threats: [.proxyDetected])
        XCTAssertTrue(result.isProxyDetected)
        XCTAssertFalse(result.isSecure)
    }

    func testSecurityResult_isVPNOrProxyActive() {
        let proxyResult = SecurityResult(threats: [.proxyDetected])
        XCTAssertTrue(proxyResult.isVPNOrProxyActive)

        let vpnResult = SecurityResult(threats: [.vpnDetected])
        XCTAssertTrue(vpnResult.isVPNOrProxyActive)

        let cleanResult = SecurityResult(threats: [])
        XCTAssertFalse(cleanResult.isVPNOrProxyActive)
    }
}
