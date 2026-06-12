//
//  ThreatHistoryStoreTests.swift
//  DeviceSecurityKit
//

import XCTest
@testable import DeviceSecurityKit

final class ThreatHistoryStoreTests: XCTestCase {

    override func tearDown() {
        ThreatHistoryStore.shared.clear()
        super.tearDown()
    }

    func testLoad_whenEmpty_returnsEmptyArray() {
        ThreatHistoryStore.shared.clear()
        XCTAssertTrue(ThreatHistoryStore.shared.load().isEmpty)
    }

    func testSaveAndLoad_roundTrips() throws {
        try XCTSkipUnless(ThreatHistoryStore.shared.isKeychainAvailable(), "Keychain unavailable in this test environment (missing entitlement)")

        let events = [
            ThreatEvent(threat: .jailbreak, severity: .critical, detectedAt: Date(), evidence: ["evidence1"]),
            ThreatEvent(threat: .debugger, severity: .high, detectedAt: Date(), evidence: [])
        ]
        ThreatHistoryStore.shared.save(events)
        XCTAssertEqual(ThreatHistoryStore.shared.load(), events)
    }

    func testSave_overwritesPreviousValue() throws {
        try XCTSkipUnless(ThreatHistoryStore.shared.isKeychainAvailable(), "Keychain unavailable in this test environment (missing entitlement)")

        let first = [ThreatEvent(threat: .jailbreak, severity: .critical, detectedAt: Date(), evidence: [])]
        let second = [ThreatEvent(threat: .debugger, severity: .high, detectedAt: Date(), evidence: [])]

        ThreatHistoryStore.shared.save(first)
        ThreatHistoryStore.shared.save(second)

        XCTAssertEqual(ThreatHistoryStore.shared.load(), second)
    }

    func testClear_removesPersistedHistory() {
        let events = [ThreatEvent(threat: .fridaDetected, severity: .critical, detectedAt: Date(), evidence: [])]
        ThreatHistoryStore.shared.save(events)
        ThreatHistoryStore.shared.clear()
        XCTAssertTrue(ThreatHistoryStore.shared.load().isEmpty)
    }
}
