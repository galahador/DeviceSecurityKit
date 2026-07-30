//
//  ThreatEventTests.swift
//  DeviceSecurityKit
//

import XCTest
@testable import DeviceSecurityKit

final class ThreatEventTests: XCTestCase {

    // MARK: - Initialization

    func testInit_storesAllFields() {
        let date = Date()
        let event = ThreatEvent(threat: .jailbreak, severity: .critical, detectedAt: date, evidence: ["a", "b"])

        XCTAssertEqual(event.threat, .jailbreak)
        XCTAssertEqual(event.severity, .critical)
        XCTAssertEqual(event.detectedAt, date)
        XCTAssertEqual(event.evidence, ["a", "b"])
    }

    func testInit_allowsEmptyEvidence() {
        let event = ThreatEvent(threat: .debugger, severity: .high, detectedAt: Date(), evidence: [])
        XCTAssertTrue(event.evidence.isEmpty)
    }

    // MARK: - Equatable / Hashable

    func testEquatable_sameValues_areEqual() {
        let date = Date()
        let a = ThreatEvent(threat: .jailbreak, severity: .critical, detectedAt: date, evidence: ["x"])
        let b = ThreatEvent(threat: .jailbreak, severity: .critical, detectedAt: date, evidence: ["x"])
        XCTAssertEqual(a, b)
        XCTAssertEqual(a.hashValue, b.hashValue)
    }

    func testEquatable_differingEvidence_areNotEqual() {
        let date = Date()
        let a = ThreatEvent(threat: .jailbreak, severity: .critical, detectedAt: date, evidence: ["x"])
        let b = ThreatEvent(threat: .jailbreak, severity: .critical, detectedAt: date, evidence: ["y"])
        XCTAssertNotEqual(a, b)
    }

    func testEquatable_differingThreat_areNotEqual() {
        let date = Date()
        let a = ThreatEvent(threat: .jailbreak, severity: .critical, detectedAt: date, evidence: [])
        let b = ThreatEvent(threat: .debugger, severity: .critical, detectedAt: date, evidence: [])
        XCTAssertNotEqual(a, b)
    }

    func testHashable_canBeUsedInSet() {
        let date = Date()
        let a = ThreatEvent(threat: .jailbreak, severity: .critical, detectedAt: date, evidence: [])
        let b = ThreatEvent(threat: .jailbreak, severity: .critical, detectedAt: date, evidence: [])
        let c = ThreatEvent(threat: .debugger, severity: .high, detectedAt: date, evidence: [])
        let set: Set<ThreatEvent> = [a, b, c]
        XCTAssertEqual(set.count, 2, "Duplicate-by-value events should collapse in a Set")
    }

    // MARK: - Codable

    func testCodable_roundTrips() throws {
        let original = ThreatEvent(
            threat: .fridaDetected,
            severity: .critical,
            detectedAt: Date(timeIntervalSince1970: 1_700_000_000),
            evidence: ["port 27042 open", "frida-server process detected"]
        )

        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ThreatEvent.self, from: data)

        XCTAssertEqual(decoded, original)
    }

    func testCodable_roundTripsArray() throws {
        let events = [
            ThreatEvent(threat: .jailbreak, severity: .critical, detectedAt: Date(), evidence: ["e1"]),
            ThreatEvent(threat: .screenRecording, severity: .high, detectedAt: Date(), evidence: [])
        ]

        let data = try JSONEncoder().encode(events)
        let decoded = try JSONDecoder().decode([ThreatEvent].self, from: data)

        XCTAssertEqual(decoded, events)
    }
}
