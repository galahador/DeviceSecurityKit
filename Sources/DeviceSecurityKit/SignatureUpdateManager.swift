//
//  SignatureUpdateManager.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 08/06/2026.
//

import Foundation
import CryptoKit

/// A category of detection signature that can be extended via a verified
/// remote manifest.
public enum SignatureCategory: String, Codable, CaseIterable, Sendable {
    case jailbreakPaths
    case jailbreakEnvVars
    case jailbreakURLSchemes
    case jailbreakTestPaths
    case debuggerProcessNames
    case debuggerEnvVars
    case emulatorPaths
    case emulatorEnvVars
    case reverseEngineeringLibraries
    case reverseEngineeringEnvVars
}

/// Additional detection signatures, grouped by category.
public struct SignatureManifest: Codable, Equatable, Sendable {
    public let version: Int
    public let entries: [SignatureCategory: [String]]

    public init(version: Int, entries: [SignatureCategory: [String]]) {
        self.version = version
        self.entries = entries
    }
}

/// Errors thrown by `SignatureUpdateManager`.
public enum SignatureUpdateError: Error, Sendable, Equatable {
    /// `update(from:)` was called before `configure(publicKey:)`.
    case notConfigured
    /// The manifest's signature did not verify against the configured public key.
    case invalidSignature
}

/// Verifies and applies remotely-distributed detection-signature updates.
/// try await SignatureUpdateManager.shared.update(from: manifestURL)
public final class SignatureUpdateManager: @unchecked Sendable {

    public static let shared = SignatureUpdateManager()

    private struct Envelope: Codable {
        let payload: Data
        let signature: Data
    }

    private let stateQueue = DispatchQueue(
        label: "com.devicesecuritykit.signatureupdate",
        attributes: .concurrent
    )

    private var _publicKeyRaw: Data?
    private var _manifest: SignatureManifest?

    private let cacheURL: URL? = {
        guard let dir = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first else {
            return nil
        }
        return dir.appendingPathComponent("com.devicesecuritykit.signature-manifest.json")
    }()

    private init() {}

    /// The most recently verified manifest, if any.
    public var currentManifest: SignatureManifest? {
        stateQueue.sync { _manifest }
    }

    /// Remote-supplied entries for `category`, or an empty array if no
    /// verified manifest has provided any. Detectors append these to their
    /// built-in static lists.
    public func entries(for category: SignatureCategory) -> [String] {
        stateQueue.sync { _manifest?.entries[category] ?? [] }
    }

    /// Stores the Ed25519 public key used to verify manifests.
    @discardableResult
    public func configure(publicKey: Curve25519.Signing.PublicKey) -> Self {
        let rawKey = publicKey.rawRepresentation
        stateQueue.sync(flags: .barrier) {
            _publicKeyRaw = rawKey
        }
        loadCachedManifestIfValid(publicKey: publicKey)
        return self
    }

    /// Fetches a signed manifest from `url`
    @discardableResult
    public func update(from url: URL, urlSession: URLSession = .shared) async throws -> SignatureManifest {
        guard let publicKey = currentPublicKey() else {
            throw SignatureUpdateError.notConfigured
        }

        let (data, _) = try await urlSession.data(from: url)
        let manifest = try verifyAndDecode(data, publicKey: publicKey)

        stateQueue.sync(flags: .barrier) {
            _manifest = manifest
        }
        cache(rawEnvelope: data)

        return manifest
    }

    // MARK: - Private

    private func currentPublicKey() -> Curve25519.Signing.PublicKey? {
        guard let raw = stateQueue.sync(execute: { _publicKeyRaw }) else { return nil }
        return try? Curve25519.Signing.PublicKey(rawRepresentation: raw)
    }

    private func verifyAndDecode(_ envelopeData: Data, publicKey: Curve25519.Signing.PublicKey) throws -> SignatureManifest {
        let envelope = try JSONDecoder().decode(Envelope.self, from: envelopeData)

        guard publicKey.isValidSignature(envelope.signature, for: envelope.payload) else {
            throw SignatureUpdateError.invalidSignature
        }

        return try JSONDecoder().decode(SignatureManifest.self, from: envelope.payload)
    }

    private func loadCachedManifestIfValid(publicKey: Curve25519.Signing.PublicKey) {
        guard let cacheURL, let data = try? Data(contentsOf: cacheURL) else { return }
        guard let manifest = try? verifyAndDecode(data, publicKey: publicKey) else { return }

        stateQueue.sync(flags: .barrier) {
            _manifest = manifest
        }
    }

    private func cache(rawEnvelope data: Data) {
        guard let cacheURL else { return }
        try? data.write(to: cacheURL, options: .atomic)
    }
}
