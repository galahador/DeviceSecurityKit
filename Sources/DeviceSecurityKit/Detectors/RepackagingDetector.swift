//
//  RepackagingDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 30/05/2026.
//

import Foundation
import DSKStaticAnalysis

public final class RepackagingDetector {

    private static let logger = SecurityLogger.security(subsystem: "RepackagingDetector")

    private static let cachedLeafHash: String? = {
        extractLeafCertificateHashFromDisk()
    }()

    // MARK: - Public

    public static func isRepackaged(expectedCertificateHash: String?) -> Bool {
#if targetEnvironment(simulator)
        return false
#else
        return checkCertificateMismatch(expected: expectedCertificateHash)
#endif
    }

    /// Returns the SHA-256 hex hash of the current leaf signing certificate.
    /// Call this during development to discover the hash you need to configure:
    /// ```
    /// #if DEBUG
    /// print("Certificate hash: \(RepackagingDetector.currentCertificateHash() ?? "nil")")
    /// #endif
    /// ```
    public static func currentCertificateHash() -> String? {
        return cachedLeafHash
    }

    // MARK: - Check: Leaf signing certificate hash must match expected value

    private static func checkCertificateMismatch(expected: String?) -> Bool {
        guard let expected, !expected.isEmpty else { return false }

        guard let hash = cachedLeafHash else {
            logger.warning("Repackaging: could not extract signing certificate — assuming compromised")
            return true
        }

        if hash != expected.lowercased() {
            logger.warning("Repackaging: signing certificate hash mismatch")
            return true
        }
        return false
    }

    // MARK: - Certificate Extraction Pipeline

    private static func extractLeafCertificateHashFromDisk() -> String? {
        guard let path = Bundle.main.executablePath,
              let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe) else {
            logger.debug("Repackaging: could not read executable binary")
            return nil
        }

        guard let hash = MachOCodeSignature.leafCertificateSHA256Hex(executableData: data) else {
            logger.debug("Repackaging: could not extract leaf certificate from code signature")
            return nil
        }

        return hash
    }
}
