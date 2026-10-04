//
//  SignedSecurityReport.swift
//  DeviceSecurityKit
//

import CryptoKit
import Foundation

public struct SignedSecurityReport: Sendable, Codable {
    public let payload: Data
    public let signature: Data
    public let publicKey: Data
    public let generatedAt: Date
    
    public init(payload: Data, signature: Data, publicKey: Data, generatedAt: Date) {
        self.payload = payload
        self.signature = signature
        self.publicKey = publicKey
        self.generatedAt = generatedAt
    }
    
    public func securityResult() throws -> SecurityResult {
        try JSONDecoder.dskReport.decode(DSKReportPayload.self, from: payload).result
    }
    
    public func nonce() throws -> String {
        try JSONDecoder.dskReport.decode(DSKReportPayload.self, from: payload).nonce
    }
    
    public func isSignatureValid() -> Bool {
        guard
            let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
            let sig = try? P256.Signing.ECDSASignature(derRepresentation: signature)
                else { return false }
        return key.isValidSignature(sig, for: payload)
    }
}

// MARK: - Internal payload envelope
struct DSKReportPayload: Codable {
    let nonce: String
    let generatedAt: Date
    let result: SecurityResult
}

// MARK: - JSON helpers
extension JSONDecoder {
    static let dskReport: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()
}

extension JSONEncoder {
    static let dskReport: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys]
        e.dateEncodingStrategy = .iso8601
        return e
    }()
}
