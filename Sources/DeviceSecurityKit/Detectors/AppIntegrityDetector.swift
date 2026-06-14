//
//  AppIntegrityDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
import DSKStaticAnalysis

public final class AppIntegrityDetector {

    private static let logger = SecurityLogger.security(subsystem: "AppIntegrityDetector")

    private static let analyzer: AppBundleAnalyzer? = try? AppBundleAnalyzer(bundlePath: Bundle.main.bundlePath)

    // MARK: - Public

    public static func isIntegrityCompromised(expectedTeamID: String? = nil) -> Bool {
        return checkCodeSignaturePresence()
            || checkCodeResourcesHashes()
            || checkMachOCodeSignature()
            || checkProvisioningProfile(expectedTeamID: expectedTeamID)
    }

    // MARK: - Check 1: _CodeSignature/CodeResources must be present

    private static func checkCodeSignaturePresence() -> Bool {
#if targetEnvironment(simulator)
        return false
#else
        guard let analyzer, analyzer.hasCodeResourcesFile() else {
            logger.warning("Code signature missing: _CodeSignature/CodeResources not found")
            return true
        }
        return false
#endif
    }

    // MARK: - Check 2: Validate file hashes against CodeResources

    private static func checkCodeResourcesHashes() -> Bool {
#if targetEnvironment(simulator)
        return false
#else
        guard let analyzer else { return false }

        let mismatches = analyzer.codeResourcesHashMismatches()
        if !mismatches.isEmpty {
            logger.warning("Hash mismatch for \(SecurityLogger.redact(mismatches.joined(separator: ","))) — file(s) have been modified")
            return true
        }
        return false
#endif
    }

    // MARK: - Check 3: Mach-O LC_CODE_SIGNATURE load command

    private static func checkMachOCodeSignature() -> Bool {
#if targetEnvironment(simulator)
        return false
#else
        guard let analyzer else { return false }

        if !analyzer.hasMachOCodeSignature() {
            logger.warning("LC_CODE_SIGNATURE load command missing — binary may be re-signed or stripped")
            return true
        }
        return false
#endif
    }

    // MARK: - Provisioning profile
    private static func checkProvisioningProfile(expectedTeamID: String?) -> Bool {
#if targetEnvironment(simulator)
        return false
#else
        guard let analyzer else { return false }

        guard let plist = analyzer.provisioningProfile() else {
            return false
        }

        // Team ID check
        if let expected = expectedTeamID {
            guard let teamIDs = plist["TeamIdentifier"] as? [String], !teamIDs.isEmpty else {
                logger.warning("TeamIdentifier missing from provisioning profile")
                return true
            }
            guard teamIDs.contains(expected) else {
                logger.warning("Team ID mismatch: expected \(SecurityLogger.redact(expected)), found \(SecurityLogger.redact(teamIDs.joined(separator: ",")))")
                return true
            }
        }

        if let bundleID = Bundle.main.bundleIdentifier,
           let entitlements = plist["Entitlements"] as? [String: Any],
           let appID = entitlements["application-identifier"] as? String {
            let isWildcard = appID.hasSuffix(".*")
            let matchesBundleID = appID.hasSuffix(".\(bundleID)")
            if !isWildcard && !matchesBundleID {
                logger.warning("App identifier mismatch: profile has \(SecurityLogger.redact(appID)), bundle is \(SecurityLogger.redact(bundleID))")
                return true
            }
        }

        return false
#endif
    }
}
