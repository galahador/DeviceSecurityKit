//
//  ClipboardMonitorTests.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 13/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class ClipboardMonitorTests: XCTestCase {

    // MARK: - Initial State

    func testWasClipboardModifiedExternally_initiallyFalse() {
        XCTAssertFalse(ClipboardMonitor.wasClipboardModifiedExternally())
    }

    func testCollectEvidence_initiallyEmpty() {
        XCTAssertTrue(ClipboardMonitor.collectEvidence().isEmpty)
    }

    func testDetectionWindowSeconds_defaultValue() {
        XCTAssertEqual(ClipboardMonitor.detectionWindowSeconds, 10.0)
    }

    func testDetectionWindowSeconds_canBeSet() {
        let original = ClipboardMonitor.detectionWindowSeconds
        defer { ClipboardMonitor.detectionWindowSeconds = original }

        ClipboardMonitor.detectionWindowSeconds = 30.0
        XCTAssertEqual(ClipboardMonitor.detectionWindowSeconds, 30.0)
    }

    // MARK: - markSensitiveCopy

    func testMarkSensitiveCopy_resetsExternalChangeFlag() {
        ClipboardMonitor.markSensitiveCopy()
        XCTAssertFalse(ClipboardMonitor.wasClipboardModifiedExternally())
    }

    // MARK: - SecurityResult Integration

    func testSecurityResult_isClipboardExfiltration() {
        let result = SecurityResult(threats: [.clipboardExfiltration])
        XCTAssertTrue(result.isClipboardExfiltration)
        XCTAssertFalse(result.isSecure)
    }

    func testThreatSeverity_clipboardExfiltration_isMedium() {
        XCTAssertEqual(SecurityThreat.clipboardExfiltration.severity, .medium)
    }

    func testThreatIsPersistent_clipboardExfiltration_isFalse() {
        XCTAssertFalse(SecurityThreat.clipboardExfiltration.isPersistent)
    }
}
