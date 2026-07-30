//
//  DSKClient+ReportSigning.swift
//  DeviceSecurityKit
//

import Foundation

public extension DSKClient {
    /// Runs all enabled detectors and returns a cryptographically signed report
    func signedCheck() throws -> SignedSecurityReport {
        try DSKReportSigner.shared.sign(performCheck())
    }

    /// Runs all enabled detectors and returns a cryptographically signed report
    func signedCheck(using signer: any DSKReportSigning) throws -> SignedSecurityReport {
        try signer.sign(performCheck())
    }
}
