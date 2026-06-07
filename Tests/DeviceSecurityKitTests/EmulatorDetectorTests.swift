//
//  EmulatorDetectorTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 07/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class EmulatorDetectorTests: XCTestCase {

    // MARK: - Simulator Baseline

    func testIsEmulator_simulator() {
        #if targetEnvironment(simulator)
        XCTAssertTrue(EmulatorDetector.isEmulator(), "Simulator should be detected as emulator")
        #endif
    }

    func testDetectEmulator_simulator_returnsHighConfidence() {
        #if targetEnvironment(simulator)
        let result = EmulatorDetector.detectEmulator()
        XCTAssertTrue(result.isEmulator)
        XCTAssertEqual(result.confidence, 1.0, "Compile-time simulator check should yield full confidence")
        XCTAssertFalse(result.detectionMethods.isEmpty)
        #endif
    }

    func testDetectEmulator_hasTimestamp() {
        let result = EmulatorDetector.detectEmulator()
        XCTAssertLessThanOrEqual(result.timestamp.timeIntervalSinceNow, 0)
        XCTAssertGreaterThan(result.timestamp.timeIntervalSinceNow, -5)
    }

    // MARK: - SecurityResult Integration

    func testSecurityResult_isEmulator() {
        let result = SecurityResult(threats: [.emulator])
        XCTAssertTrue(result.isEmulator)
        XCTAssertFalse(result.isSecure)
    }

    func testThreatSeverity_emulator_isMedium() {
        XCTAssertEqual(SecurityThreat.emulator.severity, .medium)
    }

    // MARK: - Monitor Integration

    func testMonitor_emulatorCheck_disabled() {
        let monitor = SecurityMonitor(
            configuration: .disabled.withEmulatorCheck(false)
        )
        let result = monitor.performCheck()
        XCTAssertFalse(result.isEmulator)
    }
}
