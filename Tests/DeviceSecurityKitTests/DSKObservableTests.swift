//
//  DSKObservableTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 10/06/2026.
//

import XCTest
@testable import DeviceSecurityKit

@available(iOS 15.0, *)
@MainActor
final class DSKObservableTests: XCTestCase {

    func testInit_mirrorsCurrentDSKState() {
        let observable = DSKObservable(dsk: .shared)

        XCTAssertEqual(observable.status, DSK.shared.status)
        XCTAssertEqual(observable.threatHistory, DSK.shared.threatHistory)
    }
}
