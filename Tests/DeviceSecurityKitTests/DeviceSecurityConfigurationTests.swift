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
}
