//
//  DSKReportSigner.swift
//  DeviceSecurityKit
//

import CryptoKit
import Foundation
import Security

public final class DSKReportSigner: DSKReportSigning, @unchecked Sendable {

    public static let shared = DSKReportSigner()

    private let keyQueue = DispatchQueue(label: "com.dsk.report-signer.key")
    private let keychainService = "com.dsk.signing"
    private let keychainAccount = "report-key"

    private init() {}

    // MARK: - Public API

    public func sign(_ result: SecurityResult) throws -> SignedSecurityReport {
        let now = Date()
        let inner = DSKReportPayload(nonce: UUID().uuidString, generatedAt: now, result: result)
        let payloadData = try JSONEncoder.dskReport.encode(inner)
        let sig = try signData(payloadData)
        let pubKey = try publicKeyData()
        return SignedSecurityReport(payload: payloadData, signature: sig, publicKey: pubKey, generatedAt: now)
    }

    public func publicKeyData() throws -> Data {
        #if targetEnvironment(simulator)
        return try softwareKey().publicKey.x963Representation
        #else
        return try secureEnclaveKey().publicKey.x963Representation
        #endif
    }

    /// Removes the signing key from the Keychain. The next call to `sign(_:)`
    public func deleteKey() throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: keychainAccount
        ]
        try keyQueue.sync {
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw DSKSigningError.keychainError(status)
            }
        }
    }

    // MARK: - Private

    private func signData(_ data: Data) throws -> Data {
        #if targetEnvironment(simulator)
        return try softwareKey().signature(for: data).derRepresentation
        #else
        return try secureEnclaveKey().signature(for: data).derRepresentation
        #endif
    }

    // MARK: - Secure Enclave (on-device)

    #if !targetEnvironment(simulator)
    private func secureEnclaveKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        try keyQueue.sync {
            if let existing = try loadSecureEnclaveKey() { return existing }
            return try generateSecureEnclaveKey()
        }
    }

    private func loadSecureEnclaveKey() throws -> SecureEnclave.P256.Signing.PrivateKey? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: keychainAccount,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            if status == errSecItemNotFound { return nil }
            throw DSKSigningError.keychainError(status)
        }
        do {
            return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
        } catch {
            // SE key was deleted externally (e.g. Keychain purge) — remove the stale
            let deleteQuery: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: keychainService,
                kSecAttrAccount: keychainAccount
            ]
            SecItemDelete(deleteQuery as CFDictionary)
            return nil
        }
    }

    private func generateSecureEnclaveKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        let key = try SecureEnclave.P256.Signing.PrivateKey()
        // Store the opaque metadata blob — the raw private key never leaves the SE.
        let attrs: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: keychainAccount,
            kSecValueData: key.dataRepresentation,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let status = SecItemAdd(attrs as CFDictionary, nil)
        // errSecDuplicateItem: concurrent generate race — existing key wins, that's fine.
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw DSKSigningError.keychainError(status)
        }
        return key
    }
    #endif

    // MARK: - Software key (simulator)

    #if targetEnvironment(simulator)
    private func softwareKey() throws -> P256.Signing.PrivateKey {
        try keyQueue.sync {
            if let existing = try loadSoftwareKey() { return existing }
            return try generateSoftwareKey()
        }
    }

    private func loadSoftwareKey() throws -> P256.Signing.PrivateKey? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: keychainAccount,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            if status == errSecItemNotFound { return nil }
            throw DSKSigningError.keychainError(status)
        }
        return try P256.Signing.PrivateKey(rawRepresentation: data)
    }

    private func generateSoftwareKey() throws -> P256.Signing.PrivateKey {
        let key = P256.Signing.PrivateKey()
        let attrs: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: keychainAccount,
            kSecValueData: key.rawRepresentation,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw DSKSigningError.keychainError(status)
        }
        return key
    }
    #endif
}

// MARK: - Error

public enum DSKSigningError: Error, CustomStringConvertible {
    case keychainError(OSStatus)

    public var description: String {
        switch self {
        case .keychainError(let status):
            let msg = SecCopyErrorMessageString(status, nil) as String? ?? "unknown"
            return "Keychain error (\(status)): \(msg)"
        }
    }
}
