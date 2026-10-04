//
//  DSKReportSigning.swift
//  DeviceSecurityKit
//

import Foundation

public protocol DSKReportSigning: AnyObject, Sendable {
    func sign(_ result: SecurityResult) throws -> SignedSecurityReport
    func publicKeyData() throws -> Data
    func deleteKey() throws
}
