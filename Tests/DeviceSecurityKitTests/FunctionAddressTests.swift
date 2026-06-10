//
//  FunctionAddressTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 10/06/2026.
//

import XCTest
import Darwin
@testable import DeviceSecurityKit

final class FunctionAddressTests: XCTestCase {

    func testOf_globalFunction_resolvesToCallingImage() {
        let ptr = FunctionAddress.of(functionAddressTestsSampleFunction as () -> Int)

        var info = Dl_info()
        XCTAssertNotEqual(dladdr(ptr, &info), 0, "dladdr should resolve the address returned by FunctionAddress.of")
        XCTAssertNotNil(info.dli_fname)
    }

    func testOf_staticMethod_resolvesViaDladdr() {
        let ptr = FunctionAddress.of(FunctionAddressTests.sampleStaticMethod as () -> Void)

        var info = Dl_info()
        XCTAssertNotEqual(dladdr(ptr, &info), 0)
    }

    func testOf_capturingClosure_resolvesViaDladdr() {
        let captured = 42
        let closure: () -> Int = { captured }
        let ptr = FunctionAddress.of(closure)

        var info = Dl_info()
        XCTAssertNotEqual(dladdr(ptr, &info), 0, "dladdr should resolve the code pointer even for a context-capturing closure")
    }

    private static func sampleStaticMethod() {}
}

private func functionAddressTestsSampleFunction() -> Int {
    return 1
}
