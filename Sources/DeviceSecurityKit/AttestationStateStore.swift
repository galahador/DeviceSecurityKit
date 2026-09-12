//
//  AttestationStateStore.swift
//  DeviceSecurityKit
//

import Foundation
import Security

internal struct AttestationStateStore {

    internal static let shared = AttestationStateStore()

    internal struct State: Codable, Equatable {
        internal let hasAttempted: Bool
        internal let hasFailed: Bool
    }

    private let service: String
    private let account: String

    private init() {
        let o = StringObfuscator.shared
        service = o.reveal([0xC5, 0x0D, 0xA5, 0xF1, 0x07, 0xDD, 0xCF, 0x54, 0x42, 0xC5, 0xBF, 0xB9, 0x05, 0x30, 0x2B, 0x07, 0x55, 0xD8, 0x66, 0xB5, 0x50, 0x70, 0x8E, 0xA8, 0xE8, 0xED, 0x01, 0x87, 0x2E, 0x05, 0x08, 0x28, 0x8A, 0x20, 0xA0, 0x4C, 0x59])
        account = o.reveal([0x4A, 0x5E, 0x53, 0xDA, 0xB1, 0xF7, 0x18, 0xDA, 0xE5, 0x71, 0x22, 0x25, 0x8F, 0x45, 0xD2, 0x87, 0x21, 0x03, 0x24, 0x91])
    }

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true
        ]
    }

    internal func save(_ state: State) {
        guard let data = try? JSONEncoder().encode(state) else { return }
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

    internal func load() -> State? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return try? JSONDecoder().decode(State.self, from: data)
    }

    internal func clear() {
        SecItemDelete(baseQuery() as CFDictionary)
    }

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
