//
//  SecurityResultTests.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class SecurityResultTests: XCTestCase {

    func testSecureWhenNoThreats() {
        let result = SecurityResult(threats: [])
        XCTAssertTrue(result.isSecure)
        XCTAssertFalse(result.isJailbroken)
        XCTAssertFalse(result.isDebuggerAttached)
        XCTAssertFalse(result.isEmulator)
        XCTAssertFalse(result.isReverseEngineered)
        XCTAssertFalse(result.isScreenRecorded)
    }

    func testStaticSecureConstant() {
        XCTAssertTrue(SecurityResult.secure.isSecure)
        XCTAssertTrue(SecurityResult.secure.threats.isEmpty)
    }

    func testJailbreakThreat() {
        let result = SecurityResult(threats: [.jailbreak])
        XCTAssertFalse(result.isSecure)
        XCTAssertTrue(result.isJailbroken)
        XCTAssertFalse(result.isDebuggerAttached)
    }

    func testDebuggerThreat() {
        let result = SecurityResult(threats: [.debugger])
        XCTAssertFalse(result.isSecure)
        XCTAssertFalse(result.isJailbroken)
        XCTAssertTrue(result.isDebuggerAttached)
    }

    func testMultipleThreats() {
        let result = SecurityResult(threats: [.jailbreak, .reverseEngineering])
        XCTAssertFalse(result.isSecure)
        XCTAssertTrue(result.isJailbroken)
        XCTAssertTrue(result.isReverseEngineered)
        XCTAssertEqual(result.threats.count, 2)
    }

    func testEquality() {
        let a = SecurityResult(threats: [.jailbreak])
        let b = SecurityResult(threats: [.jailbreak])
        let c = SecurityResult(threats: [.debugger])
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }

    // MARK: - generateReport

    func testGenerateReport_secure() {
        let report = SecurityResult.secure.generateReport()
        XCTAssertTrue(report.contains("Status: Secure"))
        XCTAssertTrue(report.contains("Threats Detected: 0"))
        XCTAssertTrue(report.contains("No threats detected."))
    }

    func testGenerateReport_includesThreatsAndEvidence() {
        let result = SecurityResult(
            threats: [.jailbreak, .debugger],
            evidence: [
                .jailbreak: ["suspiciousPath(\"/Applications/Cydia.app\")"],
                .debugger: ["ptraceDetected"]
            ]
        )
        let report = result.generateReport()
        XCTAssertTrue(report.contains("Status: Compromised"))
        XCTAssertTrue(report.contains("Threats Detected: 2"))
        XCTAssertTrue(report.contains("jailbreak"))
        XCTAssertTrue(report.contains("debugger"))
        XCTAssertTrue(report.contains("suspiciousPath(\"/Applications/Cydia.app\")"))
        XCTAssertTrue(report.contains("ptraceDetected"))
        // Highest severity threat should be listed first, I hope...
        let jailbreakRange = report.range(of: "jailbreak")
        let debuggerRange = report.range(of: "debugger")
        XCTAssertNotNil(jailbreakRange)
        XCTAssertNotNil(debuggerRange)
        XCTAssertTrue(jailbreakRange!.lowerBound < debuggerRange!.lowerBound)
    }
}
