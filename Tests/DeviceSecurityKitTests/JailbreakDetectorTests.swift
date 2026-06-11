//
//  JailbreakDetectorTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 07/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class JailbreakDetectorTests: XCTestCase {

    // MARK: - Simulator Baseline

    func testIsJailbroken_simulator() {
        #if targetEnvironment(simulator)
        // Simulator has no jailbreak artifacts — should return false
        XCTAssertFalse(JailbreakDetector.isJailbroken())
        #endif
    }

    func testGetDetectionDetails_simulator_isEmpty() {
        #if targetEnvironment(simulator)
        let details = JailbreakDetector.getDetectionDetails()
        XCTAssertTrue(details.isEmpty, "No jailbreak evidence expected on simulator")
        #endif
    }

    // MARK: - SecurityResult Integration

    func testSecurityResult_isJailbroken() {
        let result = SecurityResult(threats: [.jailbreak])
        XCTAssertTrue(result.isJailbroken)
        XCTAssertFalse(result.isSecure)
    }

    func testThreatSeverity_jailbreak_isCritical() {
        XCTAssertEqual(SecurityThreat.jailbreak.severity, .critical)
    }

    // MARK: - Monitor Integration

    func testMonitor_jailbreakCheck_disabled() {
        let monitor = SecurityMonitor(
            configuration: .disabled.withJailbreakCheck(false)
        )
        let result = monitor.performCheck()
        XCTAssertFalse(result.isJailbroken)
    }

    func testMonitor_jailbreakCheck_enabled_simulator() {
        #if targetEnvironment(simulator)
        let monitor = SecurityMonitor(
            configuration: .disabled.withJailbreakCheck(true)
        )
        let result = monitor.performCheck()
        XCTAssertFalse(result.isJailbroken, "Simulator should not report jailbreak")
        #endif
    }

    // MARK: - TrollStore Detection Lists

    func testJailbreakListOptions_includesTrollStorePaths() {
        let options = JailbreakListOptions()
        XCTAssertTrue(options.suspiciousPaths.contains("/Applications/TrollStore.app"))
        XCTAssertTrue(options.suspiciousPaths.contains("/Applications/TrollStore.app/Info.plist"))
        XCTAssertTrue(options.suspiciousPaths.contains("/Applications/TrollStore.app/TrollStore"))
        XCTAssertTrue(options.suspiciousPaths.contains("/var/containers/Bundle/Application/.TrollStorePersistenceHelper"))
    }

    func testJailbreakListOptions_includesTrollStoreURLScheme() {
        let options = JailbreakListOptions()
        XCTAssertTrue(options.urlSchemes.contains("apple-magnifier://"))
    }
}
