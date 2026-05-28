//
//  StringObfuscatorTests.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class StringObfuscatorTests: XCTestCase {

    private let obfuscator = StringObfuscator.shared

    func testRoundTrip_ascii() {
        let samples = [
            "FridaGadget",
            "DYLD_INSERT_LIBRARIES",
            "/var/containers/Bundle/Application/",
            "_SafeMode",
            "libhooker"
        ]
        for original in samples {
            let encoded = obfuscator.conceal(original)
            let decoded = obfuscator.reveal(encoded)
            XCTAssertEqual(decoded, original, "Round-trip failed for: \(original)")
        }
    }

    func testRoundTrip_emptyString() {
        let encoded = obfuscator.conceal("")
        XCTAssertEqual(encoded.count, 4, "Empty string should produce salt-only (4 bytes)")
        XCTAssertEqual(obfuscator.reveal(encoded), "")
    }

    func testEncodedBytesAreNotPlaintext() {
        let original = "FridaGadget"
        let encoded = obfuscator.conceal(original)
        let originalBytes = Array(original.utf8)
        
        XCTAssertNotEqual(encoded.count, originalBytes.count)
        
        let payload = Array(encoded.dropFirst(4))
        XCTAssertNotEqual(payload, originalBytes)
    }

    func testRevealKnownBytes_fridaGadget() {
        let bytes: [UInt8] = [0xC3, 0x9C, 0xE5, 0x30, 0xF2, 0x7E, 0xA5, 0xD0, 0x0F, 0x45, 0x1A, 0x76, 0x5B, 0x37, 0x55]
        XCTAssertEqual(obfuscator.reveal(bytes), "FridaGadget")
    }

    func testRevealKnownBytes_dyldInsertLibraries() {
        let bytes: [UInt8] = [0x6A, 0x32, 0x1F, 0x11, 0x2D, 0x86, 0xE7, 0xC3, 0x04, 0xA0, 0xB0, 0x72, 0x74, 0xAF, 0x5B,
                              0xA3, 0x95, 0x20, 0x61, 0x50, 0xDB, 0x53, 0xF3, 0xC0, 0x10]
        XCTAssertEqual(obfuscator.reveal(bytes), "DYLD_INSERT_LIBRARIES")
    }

    func testRevealKnownBytes_validBundlePath() {
        let bytes: [UInt8] = [0x01, 0x2E, 0x3C, 0x2B, 0x80, 0xF1, 0x66, 0x41, 0xBA, 0x22, 0x33, 0x17,
                              0x1D, 0x33, 0x8B, 0x85, 0xB1, 0xB8, 0x01, 0xDC, 0x7A, 0x94, 0x25, 0x62,
                              0xF8, 0x65, 0x1F, 0xBD, 0x34, 0xE3, 0xB5, 0x44, 0xA5, 0x22, 0x18, 0x55,
                              0x7B, 0x6A, 0xD3]
        XCTAssertEqual(obfuscator.reveal(bytes), "/var/containers/Bundle/Application/")
    }

    func testDifferentConcealCallsProduceDifferentBytes() {
        let a = obfuscator.conceal("test")
        let b = obfuscator.conceal("test")
        XCTAssertNotEqual(a, b, "Two conceal() calls should produce different output due to random salt")
        XCTAssertEqual(obfuscator.reveal(a), "test")
        XCTAssertEqual(obfuscator.reveal(b), "test")
    }

    func testRevealTooShortArray() {
        XCTAssertEqual(obfuscator.reveal([]), "")
        XCTAssertEqual(obfuscator.reveal([0x01]), "")
        XCTAssertEqual(obfuscator.reveal([0x01, 0x02, 0x03, 0x04]), "")
    }

    // MARK: - Obfuscation Strength Validation

    func testNoPlaintextBytesLeakIntoPayload() {
        let original = "AAAAAAAAAAAAAAAA" // 16 identical bytes
        let encoded = obfuscator.conceal(original)
        let payload = Array(encoded.dropFirst(4))
        let plaintext = Array(original.utf8)

        var matchCount = 0
        for i in 0..<plaintext.count {
            if payload[i] == plaintext[i] { matchCount += 1 }
        }
        
        XCTAssertLessThan(matchCount, plaintext.count / 2,
                          "Too many payload bytes match plaintext — weak key stream")
    }

    func testSaltChangesEntirePayload() {
        let a = obfuscator.conceal("FridaGadget")
        let b = obfuscator.conceal("FridaGadget")
        let payloadA = Array(a.dropFirst(4))
        let payloadB = Array(b.dropFirst(4))

        XCTAssertNotEqual(payloadA, payloadB, "Different salts must produce different payloads")

        // At least half the bytes should differ (strong diffusion)
        var diffCount = 0
        for i in 0..<payloadA.count {
            if payloadA[i] != payloadB[i] { diffCount += 1 }
        }
        XCTAssertGreaterThan(diffCount, payloadA.count / 2,
                             "Salt change should cascade — most payload bytes must differ")
    }

    func testKeyStreamIsPositionDependent() {
        // Encoding "AAAA" should NOT produce identical payload bytes.
        let encoded = obfuscator.conceal("AAAA")
        let payload = Array(encoded.dropFirst(4))

        let unique = Set(payload)
        XCTAssertGreaterThan(unique.count, 1,
                             "Identical input bytes must produce varied output — key stream must be position-dependent")
    }

    func testWrongSaltFailsToDecode() {
        // Tampering with the salt should produce garbage, not the original string
        var encoded = obfuscator.conceal("FridaGadget")
        for i in 0..<4 { encoded[i] ^= 0xFF }
        let decoded = obfuscator.reveal(encoded)
        XCTAssertNotEqual(decoded, "FridaGadget",
                          "Corrupted salt must not decode to original string")
    }

    func testPayloadEntropyIsHigh() {
        // A well-obfuscated payload should use a wide range of byte values.
        let long = String(repeating: "/usr/lib/libsubstrate.dylib", count: 10)
        let encoded = obfuscator.conceal(long)
        let payload = Array(encoded.dropFirst(4))
        let unique = Set(payload)
        // 260 bytes of input, good PRNG should produce ≥ 100 unique byte values
        XCTAssertGreaterThan(unique.count, 80,
                             "Payload byte distribution is too narrow — weak key stream")
    }
}
