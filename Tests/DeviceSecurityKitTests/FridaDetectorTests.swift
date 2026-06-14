//
//  FridaDetectorTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 07/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class FridaDetectorTests: XCTestCase {

    // MARK: - Simulator Baseline

    func testIsFridaDetected_simulator_noFrida() {
        #if targetEnvironment(simulator)
        // Port scan disabled to avoid flaky results from localhost services
        XCTAssertFalse(FridaDetector.isFridaDetected(portScanEnabled: false))
        #endif
    }

    func testIsFridaDetected_portScanDisabled() {
        let result = FridaDetector.isFridaDetected(portScanEnabled: false)
        // Without port scan, only library and symbol checks run
        // On a clean simulator these should return false
        _ = result // No assertion — just verifying it doesn't crash
    }

    func testCollectEvidence_noFrida_isEmpty() {
        #if targetEnvironment(simulator)
        let evidence = FridaDetector.collectEvidence(portScanEnabled: false)
        XCTAssertTrue(evidence.isEmpty, "No Frida evidence expected on clean simulator")
        #endif
    }

    func testDefaultPorts_containsExpectedValues() {
        XCTAssertTrue(FridaDetector.defaultPorts.contains(27042), "Should contain Frida default port")
        XCTAssertEqual(FridaDetector.defaultPorts.count, 5)
    }

    // MARK: - Frida Gadget / frida-server Signature Checks

    func testCollectEvidence_noGadgetDylibSignature() {
        #if targetEnvironment(simulator)
        let evidence = FridaDetector.collectEvidence(portScanEnabled: false)
        XCTAssertFalse(evidence.contains("fridaGadgetDylibSignature"), "No FridaGadget.dylib expected on clean simulator")
        #endif
    }

    func testCollectEvidence_noFridaServerFilesystemArtifacts() {
        #if targetEnvironment(simulator)
        let evidence = FridaDetector.collectEvidence(portScanEnabled: false)
        XCTAssertFalse(evidence.contains { $0.hasPrefix("fridaServerFilesystemArtifact") }, "No re.frida.server artifacts expected on clean simulator")
        #endif
    }

    // MARK: - SecurityResult Integration

    func testSecurityResult_isFridaDetected() {
        let result = SecurityResult(threats: [.fridaDetected])
        XCTAssertTrue(result.isFridaDetected)
        XCTAssertFalse(result.isSecure)
    }

    func testThreatSeverity_frida_isCritical() {
        XCTAssertEqual(SecurityThreat.fridaDetected.severity, .critical)
    }

    // MARK: - Monitor Integration

    func testMonitor_fridaCheck_disabled() {
        let monitor = SecurityMonitor(
            configuration: .disabled.withFridaDetection(false)
        )
        let result = monitor.performCheck()
        XCTAssertFalse(result.isFridaDetected)
    }
}
