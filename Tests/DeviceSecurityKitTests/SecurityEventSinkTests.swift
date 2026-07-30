//
//  SecurityEventSinkTests.swift
//  DeviceSecurityKit
//

import XCTest
@testable import DeviceSecurityKit

// MARK: - Helpers

private final class SpySink: SecurityEventSink, @unchecked Sendable {
    var detectedEvents: [ThreatEvent] = []
    var statusChanges: [SecurityStatus] = []
    var completedResults: [SecurityResult] = []

    func threatDetected(_ event: ThreatEvent) { detectedEvents.append(event) }
    func statusChanged(to status: SecurityStatus) { statusChanges.append(status) }
    func checkCompleted(_ result: SecurityResult) { completedResults.append(result) }
}

private final class DefaultSink: SecurityEventSink, @unchecked Sendable {
    var detectedEvents: [ThreatEvent] = []
    func threatDetected(_ event: ThreatEvent) { detectedEvents.append(event) }
    // statusChanged and checkCompleted use default no-ops
}

// MARK: - Tests

final class SecurityEventSinkTests: XCTestCase {

    // MARK: - Default no-ops

    func testDefaultImplementations_doNotCrash() {
        let sink = DefaultSink()
        sink.statusChanged(to: .secure)
        sink.checkCompleted(SecurityResult.secure)
        XCTAssertTrue(sink.detectedEvents.isEmpty)
    }

    // MARK: - Registration

    func testAddSink_isRetainedByMonitor() {
        let monitor = SecurityMonitor(configuration: .disabled)
        let sink = SpySink()
        monitor.addEventSink(sink)
        monitor.performCheck()

        let exp = expectation(description: "checkCompleted called")
        DispatchQueue.main.async { exp.fulfill() }
        wait(for: [exp], timeout: 1.0)

        XCTAssertEqual(sink.completedResults.count, 1)
    }

    func testRemoveSink_stopsReceivingEvents() {
        let monitor = SecurityMonitor(configuration: .disabled)
        let sink = SpySink()
        monitor.addEventSink(sink)
        monitor.removeEventSink(sink)
        monitor.performCheck()

        let exp = expectation(description: "main queue flush")
        DispatchQueue.main.async { exp.fulfill() }
        wait(for: [exp], timeout: 1.0)

        XCTAssertTrue(sink.completedResults.isEmpty)
    }

    func testRemoveAllSinks_stopsAllSinks() {
        let monitor = SecurityMonitor(configuration: .disabled)
        let sinkA = SpySink()
        let sinkB = SpySink()
        monitor.addEventSink(sinkA)
        monitor.addEventSink(sinkB)
        monitor.removeAllEventSinks()
        monitor.performCheck()

        let exp = expectation(description: "main queue flush")
        DispatchQueue.main.async { exp.fulfill() }
        wait(for: [exp], timeout: 1.0)

        XCTAssertTrue(sinkA.completedResults.isEmpty)
        XCTAssertTrue(sinkB.completedResults.isEmpty)
    }

    func testAddSameSinkTwice_doesNotDuplicate() {
        let monitor = SecurityMonitor(configuration: .disabled)
        let sink = SpySink()
        monitor.addEventSink(sink)
        monitor.addEventSink(sink)
        monitor.performCheck()

        let exp = expectation(description: "main queue flush")
        DispatchQueue.main.async { exp.fulfill() }
        wait(for: [exp], timeout: 1.0)

        XCTAssertEqual(sink.completedResults.count, 1, "Sink registered twice should only fire once per check")
    }

    func testMultipleDistinctSinks_allReceiveEvents() {
        let monitor = SecurityMonitor(configuration: .disabled)
        let sinkA = SpySink()
        let sinkB = SpySink()
        monitor.addEventSink(sinkA)
        monitor.addEventSink(sinkB)
        monitor.performCheck()

        let exp = expectation(description: "main queue flush")
        DispatchQueue.main.async { exp.fulfill() }
        wait(for: [exp], timeout: 1.0)

        XCTAssertEqual(sinkA.completedResults.count, 1)
        XCTAssertEqual(sinkB.completedResults.count, 1)
    }

    // MARK: - checkCompleted

    func testCheckCompleted_firesOnEveryCheck() {
        let monitor = SecurityMonitor(configuration: .disabled)
        let sink = SpySink()
        monitor.addEventSink(sink)

        monitor.performCheck()
        monitor.performCheck()
        monitor.performCheck()

        let exp = expectation(description: "main queue flush")
        DispatchQueue.main.async { exp.fulfill() }
        wait(for: [exp], timeout: 1.0)

        XCTAssertEqual(sink.completedResults.count, 3)
    }

    func testCheckCompleted_resultIsSecureOnDisabledConfig() {
        let monitor = SecurityMonitor(configuration: .disabled)
        let sink = SpySink()
        monitor.addEventSink(sink)
        monitor.performCheck()

        let exp = expectation(description: "main queue flush")
        DispatchQueue.main.async { exp.fulfill() }
        wait(for: [exp], timeout: 1.0)

        XCTAssertTrue(sink.completedResults.first?.isSecure == true)
    }

    // MARK: - DSK facade

    func testDSKFacade_addRemoveSink_compiles() {
        // Exercises DSKClient conformance — not a singleton test to avoid shared state side-effects
        let monitor = SecurityMonitor(configuration: .disabled)
        let sink = SpySink()
        monitor.addEventSink(sink)
        monitor.removeEventSink(sink)
        monitor.removeAllEventSinks()
    }

    // MARK: - Builder chaining

    func testAddEventSink_isChainable() {
        let sink = SpySink()
        let monitor = SecurityMonitor(configuration: .disabled)
        let returned = monitor.addEventSink(sink)
        XCTAssertTrue(returned === monitor)
    }

    func testRemoveEventSink_isChainable() {
        let sink = SpySink()
        let monitor = SecurityMonitor(configuration: .disabled)
        let returned = monitor.removeEventSink(sink)
        XCTAssertTrue(returned === monitor)
    }
}
