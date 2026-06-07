//
//  ScreenshotDetectorTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 07/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class ScreenshotDetectorTests: XCTestCase {

    // MARK: - Initial State

    func testWasScreenshotTaken_initiallyFalse() {
        // Without any notification, no screenshot should be reported
        XCTAssertFalse(ScreenshotDetector.wasScreenshotTaken())
    }

    func testDetectionWindowSeconds_defaultValue() {
        // Default detection window is 10 seconds
        XCTAssertEqual(ScreenshotDetector.detectionWindowSeconds, 10.0)
    }

    func testDetectionWindowSeconds_canBeSet() {
        let original = ScreenshotDetector.detectionWindowSeconds
        defer { ScreenshotDetector.detectionWindowSeconds = original }

        ScreenshotDetector.detectionWindowSeconds = 30.0
        XCTAssertEqual(ScreenshotDetector.detectionWindowSeconds, 30.0)
    }

    // MARK: - SecurityResult Integration

    func testSecurityResult_isScreenshotTaken() {
        let result = SecurityResult(threats: [.screenshotTaken])
        XCTAssertTrue(result.isScreenshotTaken)
        XCTAssertFalse(result.isSecure)
    }

    func testThreatSeverity_screenshot_isMedium() {
        XCTAssertEqual(SecurityThreat.screenshotTaken.severity, .medium)
    }
}
