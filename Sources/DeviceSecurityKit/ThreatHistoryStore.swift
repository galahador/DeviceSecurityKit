//
//  ThreatHistoryStore.swift
//  DeviceSecurityKit
//

import Foundation
import Security

/// Keychain-backed persistence for `ThreatEvent` history
internal struct ThreatHistoryStore {

    internal static let shared = ThreatHistoryStore()

    private let service: String
    private let account: String

    private init() {
        let o = StringObfuscator.shared
        service = o.reveal([0x6A, 0xF1, 0x82, 0x2B, 0x91, 0xAF, 0x83, 0xC6, 0x74, 0x2B, 0x69, 0xEB, 0x99, 0x4F, 0x0A, 0x5E, 0x9A, 0xC3, 0x5B, 0x4E, 0x10, 0xD2, 0x61, 0x1B, 0x2B, 0x7C, 0xB7, 0xD4, 0x4B, 0xF2, 0x5F, 0x2A, 0x1F, 0x61, 0x16, 0x81, 0x6F, 0xB7, 0xFA])
        account = o.reveal([0x53, 0xD9, 0xC2, 0x85, 0xF0, 0xB3, 0xEE, 0x66, 0x1F, 0x25, 0x05, 0xDC, 0x65, 0xB0, 0x4D, 0x1C, 0x74])
    }

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true
        ]
    }

    /// Persists the given threat history, replacing any previously stored value.
    internal func save(_ events: [ThreatEvent]) {
        guard let data = try? JSONEncoder().encode(events) else { return }
        let query = baseQuery()

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        if status == errSecSuccess {
            let attributes: [String: Any] = [kSecValueData as String: data]
            SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        } else {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
            SecItemAdd(addQuery as CFDictionary, nil)
        }
    }

    /// Loads the previously persisted threat history, or an empty array if none exists.
    internal func load() -> [ThreatEvent] {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return [] }
        return (try? JSONDecoder().decode([ThreatEvent].self, from: data)) ?? []
    }

    /// Removes any persisted threat history.
    internal func clear() {
        SecItemDelete(baseQuery() as CFDictionary)
    }

    /// Whether the Keychain is actually reachable in this process.
    internal func isKeychainAvailable() -> Bool {
        let probeQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
            kSecValueData as String: Data(),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        let status = SecItemAdd(probeQuery as CFDictionary, nil)
        if status == errSecSuccess {
            SecItemDelete(baseQuery() as CFDictionary)
            return true
        }
        return status != errSecMissingEntitlement
    }
}
