//
//  SecurityMonitorTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 07/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class SecurityMonitorTests: XCTestCase {

    // MARK: - Initialization

    func testInit_defaultConfiguration() {
        let monitor = SecurityMonitor()
        let result = monitor.performCheck()
        // Should return a valid result regardless of environment
        _ = result.isSecure
    }

    func testInit_disabledConfiguration() {
        let monitor = SecurityMonitor(configuration: .disabled)
        let result = monitor.performCheck()
        XCTAssertTrue(result.isSecure, "Disabled config should detect no threats")
        XCTAssertTrue(result.threats.isEmpty)
    }

    // MARK: - Configuration

    func testConfigure_updatesConfiguration() {
        let monitor = SecurityMonitor(configuration: .disabled)
        monitor.configure(.jailbreakOnly)
        let config = monitor.currentConfiguration()
        XCTAssertTrue(config.jailbreakCheckEnabled)
        XCTAssertFalse(config.debuggerCheckEnabled)
    }

    // MARK: - Monitoring Intervals

    func testMonitoringInterval_defaultValue() {
        let monitor = SecurityMonitor()
        XCTAssertEqual(monitor.monitoringInterval, 60.0)
    }

    func testMonitoringInterval_canBeSet() {
        let monitor = SecurityMonitor()
        monitor.monitoringInterval = 30.0
        XCTAssertEqual(monitor.monitoringInterval, 30.0)
    }

    func testMinMonitoringInterval_canBeSet() {
        let monitor = SecurityMonitor()
        monitor.minMonitoringInterval = 5.0
        XCTAssertEqual(monitor.minMonitoringInterval, 5.0)
    }

    func testMaxMonitoringInterval_canBeSet() {
        let monitor = SecurityMonitor()
        monitor.maxMonitoringInterval = 600.0
        XCTAssertEqual(monitor.maxMonitoringInterval, 600.0)
    }

    func testCurrentMonitoringInterval_initiallyEqualsBase() {
        let monitor = SecurityMonitor()
        monitor.monitoringInterval = 45.0
        XCTAssertEqual(monitor.currentMonitoringInterval, 45.0)
    }

    // MARK: - Threat History

    func testThreatHistory_initiallyEmpty() {
        let monitor = SecurityMonitor(configuration: .disabled)
        XCTAssertTrue(monitor.threatHistory.isEmpty)
    }

    func testThreatHistoryMaxSize_canBeSet() {
        let monitor = SecurityMonitor()
        monitor.threatHistoryMaxSize = 50
        XCTAssertEqual(monitor.threatHistoryMaxSize, 50)
    }

    func testClearThreatHistory() {
        let monitor = SecurityMonitor(configuration: .disabled)
        monitor.clearThreatHistory()
        XCTAssertTrue(monitor.threatHistory.isEmpty)
    }

    // MARK: - Threat History Persistence

    func testInit_withPersistenceEnabled_loadsPersistedHistory() throws {
        try XCTSkipUnless(ThreatHistoryStore.shared.isKeychainAvailable(), "Keychain unavailable in this test environment (missing entitlement)")

        ThreatHistoryStore.shared.clear()
        let persisted = [ThreatEvent(threat: .jailbreak, severity: .critical, detectedAt: Date(), evidence: ["persisted"])]
        ThreatHistoryStore.shared.save(persisted)
        defer { ThreatHistoryStore.shared.clear() }

        let monitor = SecurityMonitor(configuration: .disabled.withThreatHistoryPersistence(true))
        XCTAssertEqual(monitor.threatHistory, persisted)
    }

    func testInit_withPersistenceDisabled_doesNotLoadPersistedHistory() {
        ThreatHistoryStore.shared.clear()
        let persisted = [ThreatEvent(threat: .jailbreak, severity: .critical, detectedAt: Date(), evidence: ["persisted"])]
        ThreatHistoryStore.shared.save(persisted)
        defer { ThreatHistoryStore.shared.clear() }

        let monitor = SecurityMonitor(configuration: .disabled)
        XCTAssertTrue(monitor.threatHistory.isEmpty)
    }

    func testClearThreatHistory_withPersistenceEnabled_clearsKeychain() {
        ThreatHistoryStore.shared.save([ThreatEvent(threat: .debugger, severity: .high, detectedAt: Date(), evidence: [])])
        defer { ThreatHistoryStore.shared.clear() }

        let monitor = SecurityMonitor(configuration: .disabled.withThreatHistoryPersistence(true))
        monitor.clearThreatHistory()

        XCTAssertTrue(monitor.threatHistory.isEmpty)
        // Give the async persistence queue a moment to process the clear.
        let exp = expectation(description: "keychain cleared")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) {
            XCTAssertTrue(ThreatHistoryStore.shared.load().isEmpty)
            exp.fulfill()
        }
        wait(for: [exp], timeout: 1.0)
    }

    // MARK: - Callbacks

    func testOnStatusChange_returnsMonitor() {
        let monitor = SecurityMonitor()
        let returned = monitor.onStatusChange { _ in }
        XCTAssertTrue(returned === monitor)
    }

    func testOnThreatDetected_returnsMonitor() {
        let monitor = SecurityMonitor()
        let returned = monitor.onThreatDetected { _ in }
        XCTAssertTrue(returned === monitor)
    }

    func testOnThreatEvent_returnsMonitor() {
        let monitor = SecurityMonitor()
        let returned = monitor.onThreatEvent { _ in }
        XCTAssertTrue(returned === monitor)
    }

    // MARK: - Countermeasures

    func testAddCountermeasure_returnsMonitor() {
        let monitor = SecurityMonitor()
        let cm = Countermeasure(trigger: .anyThreat, throttled: false) { _ in }
        let returned = monitor.addCountermeasure(cm)
        XCTAssertTrue(returned === monitor)
    }

    func testRemoveAllCountermeasures() {
        let monitor = SecurityMonitor()
        let cm = Countermeasure(trigger: .anyThreat, throttled: false) { _ in }
        _ = monitor.addCountermeasure(cm)
        monitor.removeAllCountermeasures()
        // No crash = success; countermeasure list is private
    }

    // MARK: - Start / Stop

    func testStartAndStop_noCrash() {
        let monitor = SecurityMonitor(configuration: .disabled)
        monitor.startMonitoring()
        monitor.stopMonitoring()
    }

    // MARK: - performCheck with disabled config

    func testPerformCheck_disabledConfig_isSecure() {
        let monitor = SecurityMonitor(configuration: .disabled)
        XCTAssertTrue(monitor.isSecure)
    }

    // MARK: - Throttle Interval

    func testThrottleInterval_canBeSet() {
        let monitor = SecurityMonitor()
        monitor.threatCallbackThrottleInterval = 120.0
        XCTAssertEqual(monitor.threatCallbackThrottleInterval, 120.0)
    }

    // MARK: - Detector Diagnostics

    func testLastDetectorDiagnostics_initiallyEmpty() {
        let monitor = SecurityMonitor(configuration: .disabled)
        XCTAssertTrue(monitor.lastDetectorDiagnostics.isEmpty)
    }

    func testLastDetectorDiagnostics_populatedAfterPerformCheck() {
        let monitor = SecurityMonitor(configuration: .jailbreakOnly)
        _ = monitor.performCheck()
        let diagnostics = monitor.lastDetectorDiagnostics
        XCTAssertNotNil(diagnostics["jailbreak"])
        XCTAssertGreaterThanOrEqual(diagnostics["jailbreak"]?.duration ?? -1, 0)
        XCTAssertEqual(diagnostics["jailbreak"]?.timedOut, false)
        // dskTampered always runs regardless of configuration
        XCTAssertNotNil(diagnostics["dskTampered"])
    }
}
