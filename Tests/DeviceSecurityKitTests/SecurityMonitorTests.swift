//
//  SecurityMonitorTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 07/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

private final class StubScreenRecordingProvider: ScreenRecordingProvider, @unchecked Sendable {
    var isRecording: Bool
    init(isRecording: Bool) { self.isRecording = isRecording }
    func isScreenBeingRecorded() -> Bool { isRecording }
}

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

    // MARK: - Real Threat Pipeline (via injected ScreenRecordingProvider)

    func testPerformCheck_realThreat_populatesThreatHistory() {
        let monitor = SecurityMonitor(configuration: .disabled.withScreenRecordingCheck(true))
        monitor.screenRecordingProvider = StubScreenRecordingProvider(isRecording: true)

        let result = monitor.performCheck()

        XCTAssertTrue(result.threats.contains(.screenRecording))
        XCTAssertEqual(monitor.threatHistory.count, 1)
        XCTAssertEqual(monitor.threatHistory.first?.threat, .screenRecording)
        XCTAssertEqual(monitor.threatHistory.first?.severity, .high)
        XCTAssertEqual(monitor.threatHistory.first?.evidence, ["screenBeingRecorded"])
    }

    func testPerformCheck_realThreat_firesOnThreatEventWithMatchingEvent() {
        let monitor = SecurityMonitor(configuration: .disabled.withScreenRecordingCheck(true))
        monitor.screenRecordingProvider = StubScreenRecordingProvider(isRecording: true)

        var receivedEvent: ThreatEvent?
        var receivedThreat: SecurityThreat?
        var receivedStatus: SecurityStatus?
        monitor.onThreatEvent { receivedEvent = $0 }
        monitor.onThreatDetected { receivedThreat = $0 }
        monitor.onStatusChange { receivedStatus = $0 }

        monitor.performCheck()

        let exp = expectation(description: "main queue flush")
        DispatchQueue.main.async { exp.fulfill() }
        wait(for: [exp], timeout: 1.0)

        XCTAssertEqual(receivedThreat, .screenRecording)
        XCTAssertEqual(receivedStatus, .screenRecording)
        XCTAssertEqual(receivedEvent?.threat, .screenRecording)
        XCTAssertEqual(receivedEvent, monitor.threatHistory.first)
    }

    func testPerformCheck_sameThreatPersisting_doesNotDuplicateHistoryOrRefireCallback() {
        let monitor = SecurityMonitor(configuration: .disabled.withScreenRecordingCheck(true))
        let provider = StubScreenRecordingProvider(isRecording: true)
        monitor.screenRecordingProvider = provider

        var fireCount = 0
        monitor.onThreatEvent { _ in fireCount += 1 }

        monitor.performCheck()
        monitor.performCheck()
        monitor.performCheck()

        let exp = expectation(description: "main queue flush")
        DispatchQueue.main.async { exp.fulfill() }
        wait(for: [exp], timeout: 1.0)

        XCTAssertEqual(monitor.threatHistory.count, 1, "A threat that stays present across checks should not be recorded again")
        XCTAssertEqual(fireCount, 1, "onThreatEvent should only fire when a threat newly appears")
    }

    func testPerformCheck_threatClearing_removesStatusButKeepsHistory() {
        let monitor = SecurityMonitor(configuration: .disabled.withScreenRecordingCheck(true))
        let provider = StubScreenRecordingProvider(isRecording: true)
        monitor.screenRecordingProvider = provider

        monitor.performCheck()
        XCTAssertEqual(monitor.threatHistory.count, 1)

        provider.isRecording = false
        let result = monitor.performCheck()

        XCTAssertTrue(result.isSecure)
        XCTAssertEqual(monitor.threatHistory.count, 1, "Clearing a threat should not remove it from history")
    }

    func testThreatHistory_ringBuffer_trimsToMaxSize() {
        let monitor = SecurityMonitor(configuration: .disabled.withScreenRecordingCheck(true))
        monitor.threatHistoryMaxSize = 2
        monitor.threatCallbackThrottleInterval = 0
        let provider = StubScreenRecordingProvider(isRecording: false)
        monitor.screenRecordingProvider = provider

        for _ in 0..<4 {
            provider.isRecording = true
            monitor.performCheck()
            provider.isRecording = false
            monitor.performCheck()
        }

        XCTAssertEqual(monitor.threatHistory.count, 2, "Ring buffer should never exceed threatHistoryMaxSize")
        XCTAssertTrue(monitor.threatHistory.allSatisfy { $0.threat == .screenRecording })
    }

    func testThreatHistoryMaxSize_reducingSize_trimsOldestFirst() {
        let monitor = SecurityMonitor(configuration: .disabled.withScreenRecordingCheck(true))
        monitor.threatCallbackThrottleInterval = 0
        let provider = StubScreenRecordingProvider(isRecording: false)
        monitor.screenRecordingProvider = provider

        for _ in 0..<3 {
            provider.isRecording = true
            monitor.performCheck()
            provider.isRecording = false
            monitor.performCheck()
        }
        XCTAssertEqual(monitor.threatHistory.count, 3)

        monitor.threatHistoryMaxSize = 1
        XCTAssertEqual(monitor.threatHistory.count, 1)
    }

    // MARK: - Integration: configure -> performCheck -> callbacks -> history -> adaptive interval

    func testIntegration_startMonitoring_withRealThreat_updatesEverything() {
        let monitor = SecurityMonitor(configuration: .disabled.withScreenRecordingCheck(true))
        let provider = StubScreenRecordingProvider(isRecording: true)
        monitor.screenRecordingProvider = provider
        monitor.monitoringInterval = 60.0
        monitor.minMonitoringInterval = 5.0

        var statusEvents: [SecurityStatus] = []
        var threatEvents: [ThreatEvent] = []
        monitor.onStatusChange { statusEvents.append($0) }
        monitor.onThreatEvent { threatEvents.append($0) }

        monitor.startMonitoring()
        defer { monitor.stopMonitoring() }

        let exp = expectation(description: "main queue flush")
        DispatchQueue.main.async { exp.fulfill() }
        wait(for: [exp], timeout: 1.0)

        XCTAssertEqual(statusEvents, [.screenRecording])
        XCTAssertEqual(threatEvents.map(\.threat), [.screenRecording])
        XCTAssertEqual(monitor.threatHistory.count, 1)
        XCTAssertEqual(monitor.currentMonitoringInterval, monitor.minMonitoringInterval)
    }

    func testIntegration_startMonitoring_noThreats_backsOffTowardMax() {
        let monitor = SecurityMonitor(configuration: .disabled)
        monitor.monitoringInterval = 1.0
        monitor.minMonitoringInterval = 0.1
        monitor.maxMonitoringInterval = 10.0

        monitor.startMonitoring()
        defer { monitor.stopMonitoring() }

        XCTAssertGreaterThan(monitor.currentMonitoringInterval, monitor.monitoringInterval, "First clean cycle should back the interval off above the base interval")
        XCTAssertTrue(monitor.threatHistory.isEmpty)
    }
}
