//
//  DeviceSecurityConfigurationTests.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class DeviceSecurityConfigurationTests: XCTestCase {

    func testDefaultPreset_allEnabled() {
        let config = DeviceSecurityConfiguration.default
        XCTAssertTrue(config.jailbreakCheckEnabled)
        XCTAssertTrue(config.debuggerCheckEnabled)
        XCTAssertTrue(config.emulatorCheckEnabled)
        XCTAssertTrue(config.reverseEngineeringCheckEnabled)
    }

    func testDisabledPreset_allDisabled() {
        let config = DeviceSecurityConfiguration.disabled
        XCTAssertFalse(config.jailbreakCheckEnabled)
        XCTAssertFalse(config.debuggerCheckEnabled)
        XCTAssertFalse(config.emulatorCheckEnabled)
        XCTAssertFalse(config.reverseEngineeringCheckEnabled)
    }

    func testJailbreakOnlyPreset() {
        let config = DeviceSecurityConfiguration.jailbreakOnly
        XCTAssertTrue(config.jailbreakCheckEnabled)
        XCTAssertFalse(config.debuggerCheckEnabled)
        XCTAssertFalse(config.emulatorCheckEnabled)
        XCTAssertFalse(config.reverseEngineeringCheckEnabled)
    }

    func testProductionPreset_allEnabled() {
        let config = DeviceSecurityConfiguration.production
        XCTAssertTrue(config.jailbreakCheckEnabled)
        XCTAssertTrue(config.debuggerCheckEnabled)
        XCTAssertTrue(config.emulatorCheckEnabled)
        XCTAssertTrue(config.reverseEngineeringCheckEnabled)
    }

    func testBuilderPattern_disableJailbreak() {
        let config = DeviceSecurityConfiguration.default
            .withJailbreakCheck(false)
        XCTAssertFalse(config.jailbreakCheckEnabled)
        XCTAssertTrue(config.debuggerCheckEnabled)
    }

    func testBuilderPattern_chained() {
        let config = DeviceSecurityConfiguration.default
            .withJailbreakCheck(false)
            .withDebuggerCheck(false)
            .withEmulatorCheck(true)
            .withReverseEngineeringCheck(false)
        XCTAssertFalse(config.jailbreakCheckEnabled)
        XCTAssertFalse(config.debuggerCheckEnabled)
        XCTAssertTrue(config.emulatorCheckEnabled)
        XCTAssertFalse(config.reverseEngineeringCheckEnabled)
    }

    func testBuilderPattern_isNonMutating() {
        let original = DeviceSecurityConfiguration.default
        let modified = original.withJailbreakCheck(false)
        XCTAssertTrue(original.jailbreakCheckEnabled, "Builder must not mutate the original")
        XCTAssertFalse(modified.jailbreakCheckEnabled)
    }

    func testEquality() {
        // .production enables screenshotDetection (and others) that .default leaves off
        XCTAssertNotEqual(DeviceSecurityConfiguration.default, DeviceSecurityConfiguration.production)
        XCTAssertNotEqual(DeviceSecurityConfiguration.default, DeviceSecurityConfiguration.disabled)
    }

    // MARK: - Threat History Persistence

    func testThreatHistoryPersistence_disabledByDefault() {
        XCTAssertFalse(DeviceSecurityConfiguration.default.threatHistoryPersistenceEnabled)
    }

    func testWithThreatHistoryPersistence_enables() {
        let config = DeviceSecurityConfiguration.default.withThreatHistoryPersistence(true)
        XCTAssertTrue(config.threatHistoryPersistenceEnabled)
    }

    func testWithThreatHistoryPersistence_isNonMutating() {
        let original = DeviceSecurityConfiguration.default
        let modified = original.withThreatHistoryPersistence(true)
        XCTAssertFalse(original.threatHistoryPersistenceEnabled)
        XCTAssertTrue(modified.threatHistoryPersistenceEnabled)
    }

    // MARK: - MDM Detection

    func testMDMDetection_disabledByDefault() {
        XCTAssertFalse(DeviceSecurityConfiguration.default.mdmDetectionEnabled)
    }

    func testWithMDMDetection_enables() {
        let config = DeviceSecurityConfiguration.default.withMDMDetection(true)
        XCTAssertTrue(config.mdmDetectionEnabled)
    }

    func testWithMDMDetection_isNonMutating() {
        let original = DeviceSecurityConfiguration.default
        let modified = original.withMDMDetection(true)
        XCTAssertFalse(original.mdmDetectionEnabled)
        XCTAssertTrue(modified.mdmDetectionEnabled)
    }

    // MARK: - Clipboard Monitoring

    func testClipboardMonitoring_disabledByDefault() {
        XCTAssertFalse(DeviceSecurityConfiguration.default.clipboardMonitoringEnabled)
    }

    func testWithClipboardMonitoring_enables() {
        let config = DeviceSecurityConfiguration.default.withClipboardMonitoring(true)
        XCTAssertTrue(config.clipboardMonitoringEnabled)
    }

    func testWithClipboardMonitoring_isNonMutating() {
        let original = DeviceSecurityConfiguration.default
        let modified = original.withClipboardMonitoring(true)
        XCTAssertFalse(original.clipboardMonitoringEnabled)
        XCTAssertTrue(modified.clipboardMonitoringEnabled)
    }

    // MARK: - External Display Detection

    func testExternalDisplayDetection_disabledByDefault() {
        XCTAssertFalse(DeviceSecurityConfiguration.default.externalDisplayDetectionEnabled)
    }

    func testWithExternalDisplayDetection_enables() {
        let config = DeviceSecurityConfiguration.default.withExternalDisplayDetection(true)
        XCTAssertTrue(config.externalDisplayDetectionEnabled)
    }

    func testWithExternalDisplayDetection_isNonMutating() {
        let original = DeviceSecurityConfiguration.default
        let modified = original.withExternalDisplayDetection(true)
        XCTAssertFalse(original.externalDisplayDetectionEnabled)
        XCTAssertTrue(modified.externalDisplayDetectionEnabled)
    }
}
