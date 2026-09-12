//
//  AttestationStateStoreTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 12/09/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class AttestationStateStoreTests: XCTestCase {

    override func tearDown() {
        AttestationStateStore.shared.clear()
        super.tearDown()
    }

    func testLoad_whenEmpty_returnsNil() {
        AttestationStateStore.shared.clear()
        XCTAssertNil(AttestationStateStore.shared.load())
    }

    func testSaveAndLoad_roundTrips() throws {
        try XCTSkipUnless(AttestationStateStore.shared.isKeychainAvailable(), "Keychain unavailable in this test environment (missing entitlement)")

        let state = AttestationStateStore.State(hasAttempted: true, hasFailed: true)
        AttestationStateStore.shared.save(state)
        XCTAssertEqual(AttestationStateStore.shared.load(), state)
    }

    func testSave_overwritesPreviousValue() throws {
        try XCTSkipUnless(AttestationStateStore.shared.isKeychainAvailable(), "Keychain unavailable in this test environment (missing entitlement)")

        let first = AttestationStateStore.State(hasAttempted: true, hasFailed: true)
        let second = AttestationStateStore.State(hasAttempted: true, hasFailed: false)

        AttestationStateStore.shared.save(first)
        AttestationStateStore.shared.save(second)

        XCTAssertEqual(AttestationStateStore.shared.load(), second)
    }

    func testClear_removesPersistedState() {
        let state = AttestationStateStore.State(hasAttempted: true, hasFailed: true)
        AttestationStateStore.shared.save(state)
        AttestationStateStore.shared.clear()
        XCTAssertNil(AttestationStateStore.shared.load())
    }
}
