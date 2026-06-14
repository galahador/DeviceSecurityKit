//
//  KeyboardExtensionMonitorTests.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 13/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class KeyboardExtensionMonitorTests: XCTestCase {

    override func tearDown() {
        KeyboardExtensionMonitor.stopObserving()
        super.tearDown()
    }

    // MARK: - Initial State

    func testIsThirdPartyKeyboardActive_initiallyFalse() {
        XCTAssertFalse(KeyboardExtensionMonitor.isThirdPartyKeyboardActive())
    }

    func testCollectEvidence_initiallyEmpty() {
        XCTAssertTrue(KeyboardExtensionMonitor.collectEvidence().isEmpty)
    }

    func testDetectionWindowSeconds_defaultValue() {
        XCTAssertEqual(KeyboardExtensionMonitor.detectionWindowSeconds, 10.0)
    }

    func testDetectionWindowSeconds_canBeSet() {
        let original = KeyboardExtensionMonitor.detectionWindowSeconds
        defer { KeyboardExtensionMonitor.detectionWindowSeconds = original }

        KeyboardExtensionMonitor.detectionWindowSeconds = 30.0
        XCTAssertEqual(KeyboardExtensionMonitor.detectionWindowSeconds, 30.0)
    }

    // MARK: - markSensitiveFieldInactive

    func testMarkSensitiveFieldInactive_doesNotCrash() {
        KeyboardExtensionMonitor.markSensitiveFieldInactive()
        XCTAssertFalse(KeyboardExtensionMonitor.isThirdPartyKeyboardActive())
    }

    // MARK: - Observation Lifecycle

    func testStartStopObserving_doesNotCrash() {
        KeyboardExtensionMonitor.startObserving()
        KeyboardExtensionMonitor.startObserving() // safe to call multiple times
        KeyboardExtensionMonitor.stopObserving()
        KeyboardExtensionMonitor.stopObserving()
    }

    // MARK: - SecurityResult Integration

    func testSecurityResult_isThirdPartyKeyboardActive() {
        let result = SecurityResult(threats: [.thirdPartyKeyboardActive])
        XCTAssertTrue(result.isThirdPartyKeyboardActive)
        XCTAssertFalse(result.isSecure)
    }

    func testThreatSeverity_thirdPartyKeyboardActive_isMedium() {
        XCTAssertEqual(SecurityThreat.thirdPartyKeyboardActive.severity, .medium)
    }

    func testThreatIsPersistent_thirdPartyKeyboardActive_isFalse() {
        XCTAssertFalse(SecurityThreat.thirdPartyKeyboardActive.isPersistent)
    }
}
