//
//  StringObfuscator.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

internal struct StringObfuscator {

    // MARK: - Shared instance

    internal static let shared = StringObfuscator()

    // MARK: - Key Material

    private static let masterKey: [UInt8] = [
        0x3F, 0xA7, 0x12, 0xE5, 0x8B, 0x4D, 0xC1, 0x69,
        0x92, 0x5E, 0x0A, 0xF3, 0x76, 0xD8, 0x2C, 0xB4
    ]

    private static let saltLength = 4

    private init() {}

    // MARK: - Decoding

    // Encoded format: [salt₀, salt₁, salt₂, salt₃, payload₀, payload₁, ...]
    internal func reveal(_ encoded: [UInt8]) -> String {
        let saltLen = Self.saltLength
        guard encoded.count > saltLen else { return "" }
        let salt = Array(encoded.prefix(saltLen))
        let payload = Array(encoded.dropFirst(saltLen))
        let keyStream = Self.deriveKeyStream(salt: salt, length: payload.count)
        let decoded = zip(payload, keyStream).map { $0 ^ $1 }
        return String(bytes: decoded, encoding: .utf8) ?? ""
    }

    // MARK: - Key Derivation

    private static func deriveKeyStream(salt: [UInt8], length: Int) -> [UInt8] {
        var state = masterKey
        for i in 0..<state.count {
            state[i] ^= salt[i % saltLength]
            state[i] = state[i] &+ salt[(i &+ 1) % saltLength]
        }
        var stream = [UInt8]()
        stream.reserveCapacity(length)
        for i in 0..<length {
            let a = i % state.count
            let b = (i &+ 7) % state.count
            state[a] = (state[a] &+ state[b]) ^ UInt8(truncatingIfNeeded: i)
            stream.append(state[a])
        }
        return stream
    }

    // MARK: - Encoding (development only)

#if DEBUG
    internal func conceal(_ string: String) -> [UInt8] {
        let plaintext = Array(string.utf8)
        var salt = [UInt8](repeating: 0, count: Self.saltLength)
        for i in 0..<salt.count {
            salt[i] = UInt8.random(in: 0...UInt8.max)
        }
        let keyStream = Self.deriveKeyStream(salt: salt, length: plaintext.count)
        let encoded = zip(plaintext, keyStream).map { $0 ^ $1 }
        return salt + encoded
    }
#endif
}
