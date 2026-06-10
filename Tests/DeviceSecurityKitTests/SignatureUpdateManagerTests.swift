//
//  SignatureUpdateManagerTests.swift
//  DeviceSecurityKit
//
//  Created by tBug on 10/06/2026.
//

import XCTest
import CryptoKit
@testable import DeviceSecurityKit

private struct TestEnvelope: Codable {
    let payload: Data
    let signature: Data
}

private final class StubURLProtocol: URLProtocol {
    static var responseData: Data = Data()

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: StubURLProtocol.responseData)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

final class SignatureUpdateManagerTests: XCTestCase {

    private func stubSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        return URLSession(configuration: config)
    }

    private func envelope(for manifest: SignatureManifest, signingKey: Curve25519.Signing.PrivateKey) throws -> Data {
        let payload = try JSONEncoder().encode(manifest)
        let signature = try signingKey.signature(for: payload)
        return try JSONEncoder().encode(TestEnvelope(payload: payload, signature: signature))
    }

    // MARK: - Pure model tests

    func testSignatureManifest_codableRoundTrip() throws {
        let manifest = SignatureManifest(
            version: 3,
            entries: [
                .jailbreakPaths: ["/usr/sbin/sshd", "/Applications/Cydia.app"],
                .debuggerProcessNames: ["frida-server"],
            ]
        )

        let data = try JSONEncoder().encode(manifest)
        let decoded = try JSONDecoder().decode(SignatureManifest.self, from: data)

        XCTAssertEqual(decoded, manifest)
    }

    func testSignatureCategory_allCasesAreUnique() {
        let cases = SignatureCategory.allCases
        XCTAssertEqual(cases.count, 10)
        XCTAssertEqual(Set(cases.map(\.rawValue)).count, cases.count)
    }

    func testSignatureUpdateError_equatable() {
        XCTAssertEqual(SignatureUpdateError.notConfigured, .notConfigured)
        XCTAssertEqual(SignatureUpdateError.invalidSignature, .invalidSignature)
        XCTAssertNotEqual(SignatureUpdateError.notConfigured, .invalidSignature)
    }

    // MARK: - configure(publicKey:)

    func testConfigure_returnsSharedInstance() {
        let key = Curve25519.Signing.PrivateKey().publicKey
        let result = SignatureUpdateManager.shared.configure(publicKey: key)
        XCTAssertTrue(result === SignatureUpdateManager.shared)
    }

    // MARK: - update(from:)

    func testUpdate_validSignature_updatesManifestAndEntries() async throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        SignatureUpdateManager.shared.configure(publicKey: privateKey.publicKey)

        let manifest = SignatureManifest(
            version: 7,
            entries: [.emulatorPaths: ["/dev/qemu_pipe"]]
        )
        StubURLProtocol.responseData = try envelope(for: manifest, signingKey: privateKey)

        let result = try await SignatureUpdateManager.shared.update(
            from: URL(string: "https://example.com/manifest.json")!,
            urlSession: stubSession()
        )

        XCTAssertEqual(result, manifest)
        XCTAssertEqual(SignatureUpdateManager.shared.currentManifest, manifest)
        XCTAssertEqual(SignatureUpdateManager.shared.entries(for: .emulatorPaths), ["/dev/qemu_pipe"])
        XCTAssertEqual(SignatureUpdateManager.shared.entries(for: .jailbreakPaths), [])
    }

    func testUpdate_signatureFromWrongKey_throwsInvalidSignature() async throws {
        let configuredKey = Curve25519.Signing.PrivateKey()
        let attackerKey = Curve25519.Signing.PrivateKey()
        SignatureUpdateManager.shared.configure(publicKey: configuredKey.publicKey)

        let manifest = SignatureManifest(version: 1, entries: [.jailbreakEnvVars: ["DYLD_INSERT_LIBRARIES"]])
        StubURLProtocol.responseData = try envelope(for: manifest, signingKey: attackerKey)

        do {
            _ = try await SignatureUpdateManager.shared.update(
                from: URL(string: "https://example.com/manifest.json")!,
                urlSession: stubSession()
            )
            XCTFail("Expected invalidSignature error")
        } catch let error as SignatureUpdateError {
            XCTAssertEqual(error, .invalidSignature)
        }
    }
}
