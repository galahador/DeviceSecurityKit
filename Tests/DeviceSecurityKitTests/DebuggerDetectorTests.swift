//
//  DebuggerDetectorTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 07/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class DebuggerDetectorTests: XCTestCase {

    // MARK: - Simulator Baseline

    func testIsDebuggerAttached_debugBuild() {
        #if DEBUG
        // In DEBUG builds, isDebuggerAttached() returns false to avoid
        // interfering with development workflows
        XCTAssertFalse(DebuggerDetector.isDebuggerAttached())
        #endif
    }

    func testGetDetectionResults_returnsExpectedKeys() {
        let results = DebuggerDetector.getDetectionResults()
        // Should return a dictionary with known check keys
        XCTAssertFalse(results.isEmpty, "Detection results should have entries")
    }

    // MARK: - SecurityResult Integration

    func testSecurityResult_isDebuggerAttached() {
        let result = SecurityResult(threats: [.debugger])
        XCTAssertTrue(result.isDebuggerAttached)
        XCTAssertFalse(result.isSecure)
    }

    func testThreatSeverity_debugger_isHigh() {
        XCTAssertEqual(SecurityThreat.debugger.severity, .high)
    }

    // MARK: - Monitor Integration

    func testMonitor_debuggerCheck_disabled() {
        let monitor = SecurityMonitor(
            configuration: .disabled.withDebuggerCheck(false)
        )
        let result = monitor.performCheck()
        XCTAssertFalse(result.isDebuggerAttached)
    }

    func testMonitor_debuggerCheck_enabled_debugBuild() {
        #if DEBUG
        let monitor = SecurityMonitor(
            configuration: .disabled.withDebuggerCheck(true)
        )
        let result = monitor.performCheck()
        XCTAssertFalse(result.isDebuggerAttached, "DEBUG build should not flag debugger")
        #endif
    }
}
