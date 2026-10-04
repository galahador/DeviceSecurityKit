//
//  DSKClient+ReportSigning.swift
//  DeviceSecurityKit
//

import Foundation

public extension DSKClient {
    func signedCheck() throws -> SignedSecurityReport {
        try DSKReportSigner.shared.sign(performCheck())
    }

    func signedCheck(using signer: any DSKReportSigning) throws -> SignedSecurityReport {
        try signer.sign(performCheck())
    }
}
