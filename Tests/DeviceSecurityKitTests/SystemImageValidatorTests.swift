//
//  SystemImageValidatorTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 10/06/2026.
//

import XCTest
import Darwin
@testable import DeviceSecurityKit

final class SystemImageValidatorTests: XCTestCase {

    func testIsSystemImage_appBinary_isFalse() {
        guard let appImagePath = Bundle.main.executablePath else {
            return XCTFail("Expected a main bundle executable path")
        }
        XCTAssertFalse(SystemImageValidator.shared.isSystemImage(appImagePath))
    }

    func testIsSystemImage_foundationFramework_isTrue() {
        // Resolve the image backing a well-known Foundation C symbol at runtime,
        // so this test doesn't depend on the obfuscated prefix list's exact contents.
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "NSStringFromClass") else {
            return XCTFail("Could not locate NSStringFromClass via dlsym")
        }

        var info = Dl_info()
        guard dladdr(sym, &info) != 0, let fname = info.dli_fname else {
            return XCTFail("Could not resolve Foundation image via dladdr")
        }
        let foundationImagePath = String(cString: fname)

        XCTAssertTrue(SystemImageValidator.shared.isSystemImage(foundationImagePath), "path was \(foundationImagePath)")
    }

    func testIsSystemImage_unrelatedPath_isFalse() {
        XCTAssertFalse(SystemImageValidator.shared.isSystemImage("/private/var/mobile/Containers/Data/Application/evil"))
    }

    func testIsSystemImage_emptyPath_isFalse() {
        XCTAssertFalse(SystemImageValidator.shared.isSystemImage(""))
    }
}
