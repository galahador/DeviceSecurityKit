//
//  DSKReportSigning.swift
//  DeviceSecurityKit
//

import Foundation

public protocol DSKReportSigning: AnyObject, Sendable {

    func sign(_ result: SecurityResult) throws -> SignedSecurityReport

    /// Returns the raw P256 public key in ANSI format (65 bytes).
    func publicKeyData() throws -> Data

    /// Removes the persisted key, forcing a new one to be generated on the next call.
    func deleteKey() throws
}
