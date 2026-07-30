//
//  DSKReportSignerTests.swift
//  DeviceSecurityKitTests
//

import CryptoKit
import XCTest
@testable import DeviceSecurityKit

// MARK: - Test double

private final class EphemeralReportSigner: DSKReportSigning {
    private let key = P256.Signing.PrivateKey()

    func sign(_ result: SecurityResult) throws -> SignedSecurityReport {
        let now = Date()
        let inner = DSKReportPayload(nonce: UUID().uuidString, generatedAt: now, result: result)
        let payloadData = try JSONEncoder.dskReport.encode(inner)
        let sig = try key.signature(for: payloadData).derRepresentation
        return SignedSecurityReport(
            payload: payloadData,
            signature: sig,
            publicKey: key.publicKey.x963Representation,
            generatedAt: now
        )
    }

    func publicKeyData() throws -> Data {
        key.publicKey.x963Representation
    }

    func deleteKey() throws {}
}

// MARK: - Tests

final class DSKReportSignerTests: XCTestCase {

    private var signer: EphemeralReportSigner!

    override func setUp() {
        super.setUp()
        signer = EphemeralReportSigner()
    }

    // MARK: - Signature validity

    func testSign_producesValidSignature() throws {
        let result = SecurityResult(threats: [.jailbreak], evidence: [.jailbreak: ["suspicious path"]])
        let report = try signer.sign(result)
        XCTAssertTrue(report.isSignatureValid())
    }

    func testSign_secureResult_producesValidSignature() throws {
        let report = try signer.sign(.secure)
        XCTAssertTrue(report.isSignatureValid())
    }

    func testIsSignatureValid_rejectsModifiedPayload() throws {
        let report = try signer.sign(SecurityResult(threats: [.jailbreak], evidence: [:]))
        var tampered = report.payload
        tampered[0] ^= 0xFF
        let bad = SignedSecurityReport(
            payload: tampered,
            signature: report.signature,
            publicKey: report.publicKey,
            generatedAt: report.generatedAt
        )
        XCTAssertFalse(bad.isSignatureValid())
    }

    func testIsSignatureValid_rejectsWrongSignature() throws {
        let r1 = try signer.sign(.secure)
        let r2 = try signer.sign(SecurityResult(threats: [.debugger], evidence: [:]))
        let bad = SignedSecurityReport(
            payload: r1.payload,
            signature: r2.signature,
            publicKey: r1.publicKey,
            generatedAt: r1.generatedAt
        )
        XCTAssertFalse(bad.isSignatureValid())
    }

    // MARK: - Payload round-trip

    func testSign_securityResultRoundTrips() throws {
        let result = SecurityResult(
            threats: [.jailbreak, .debugger],
            evidence: [.jailbreak: ["path1", "path2"], .debugger: ["sysctl"]]
        )
        let report = try signer.sign(result)
        let decoded = try report.securityResult()
        XCTAssertEqual(
            decoded.threats.sorted(by: { $0.rawValue < $1.rawValue }),
            result.threats.sorted(by: { $0.rawValue < $1.rawValue })
        )
        XCTAssertEqual(decoded.evidence(for: .jailbreak), result.evidence(for: .jailbreak))
    }

    func testSign_secureResultRoundTrips() throws {
        let report = try signer.sign(.secure)
        XCTAssertTrue(try report.securityResult().isSecure)
    }

    // MARK: - Nonce and uniqueness

    func testSign_uniqueNonces() throws {
        let r1 = try signer.sign(.secure)
        let r2 = try signer.sign(.secure)
        XCTAssertNotEqual(try r1.nonce(), try r2.nonce())
    }

    func testSign_uniquePayloads() throws {
        let r1 = try signer.sign(.secure)
        let r2 = try signer.sign(.secure)
        XCTAssertNotEqual(r1.payload, r2.payload)
    }

    func testSign_uniqueSignatures() throws {
        let r1 = try signer.sign(.secure)
        let r2 = try signer.sign(.secure)
        XCTAssertNotEqual(r1.signature, r2.signature)
    }

    func testNonce_isValidUUID() throws {
        let report = try signer.sign(.secure)
        XCTAssertNotNil(UUID(uuidString: try report.nonce()))
    }

    // MARK: - Public key

    func testPublicKey_is65Bytes() throws {
        XCTAssertEqual(try signer.publicKeyData().count, 65)
    }

    func testPublicKey_hasUncompressedPointPrefix() throws {
        XCTAssertEqual(try signer.publicKeyData()[0], 0x04)
    }

    func testPublicKey_isStableAcrossCalls() throws {
        XCTAssertEqual(try signer.publicKeyData(), try signer.publicKeyData())
    }

    func testPublicKey_matchesEmbeddedKeyInReport() throws {
        let pubKey = try signer.publicKeyData()
        let report = try signer.sign(.secure)
        XCTAssertEqual(report.publicKey, pubKey)
    }

    // MARK: - Key lifecycle

    func testDifferentSignerInstances_haveDifferentKeys() throws {
        let other = EphemeralReportSigner()
        XCTAssertNotEqual(try signer.publicKeyData(), try other.publicKeyData())
    }

    func testNewSigner_producesValidSignatureWithOwnKey() throws {
        let other = EphemeralReportSigner()
        let report = try other.sign(.secure)
        XCTAssertTrue(report.isSignatureValid())
    }

    func testReport_signatureInvalidWithDifferentKey() throws {
        let other = EphemeralReportSigner()
        let report = try signer.sign(.secure)
        // Replace public key with the other signer's key — verification must fail
        let wrongKey = SignedSecurityReport(
            payload: report.payload,
            signature: report.signature,
            publicKey: try other.publicKeyData(),
            generatedAt: report.generatedAt
        )
        XCTAssertFalse(wrongKey.isSignatureValid())
    }

    // MARK: - Integration via DSKClient

    func testSignedCheck_producesValidReport() throws {
        let report = try DSK.shared.signedCheck(using: signer)
        XCTAssertTrue(report.isSignatureValid())
        XCTAssertFalse(report.payload.isEmpty)
        XCTAssertEqual(report.publicKey.count, 65)
    }

    func testSignedCheck_resultIsDecodable() throws {
        let report = try DSK.shared.signedCheck(using: signer)
        XCTAssertNoThrow(try report.securityResult())
        XCTAssertNoThrow(try report.nonce())
    }
}
