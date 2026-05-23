//
//  AppIntegrityDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

public final class AppIntegrityDetector {

    private static let logger = SecurityLogger.security(subsystem: "AppIntegrityDetector")

    // MARK: - Public

    public static func isIntegrityCompromised(expectedTeamID: String? = nil) -> Bool {
        return checkCodeSignaturePresence()
            || checkProvisioningProfile(expectedTeamID: expectedTeamID)
    }

    // MARK: - Check 1: _CodeSignature/CodeResources must be present

    private static func checkCodeSignaturePresence() -> Bool {
#if targetEnvironment(simulator)
        return false
#else
        let path = Bundle.main.bundlePath + "/_CodeSignature/CodeResources"
        guard FileManager.default.fileExists(atPath: path) else {
            logger.warning("Code signature missing: _CodeSignature/CodeResources not found")
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
        guard let profilePath = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision"),
              let profileData = FileManager.default.contents(atPath: profilePath) else {
            return false
        }

        guard let plist = extractPlist(from: profileData) else {
            logger.warning("Could not parse embedded.mobileprovision — treating as tampered")
            return true
        }

        // Team ID check
        if let expected = expectedTeamID {
            guard let teamIDs = plist["TeamIdentifier"] as? [String], !teamIDs.isEmpty else {
                logger.warning("TeamIdentifier missing from provisioning profile")
                return true
            }
            guard teamIDs.contains(expected) else {
                logger.warning("Team ID mismatch: expected \(expected), found \(teamIDs)")
                return true
            }
        }

        // App identifier cross-check
        if let bundleID = Bundle.main.bundleIdentifier,
           let entitlements = plist["Entitlements"] as? [String: Any],
           let appID = entitlements["application-identifier"] as? String {
            // appID format: "TEAMID.com.example.app" or "TEAMID.*"
            let isWildcard = appID.hasSuffix(".*")
            let matchesBundleID = appID.hasSuffix(".\(bundleID)")
            if !isWildcard && !matchesBundleID {
                logger.warning("App identifier mismatch: profile has \(appID), bundle is \(bundleID)")
                return true
            }
        }

        return false
#endif
    }

    // MARK: - Helpers
    private static func extractPlist(from data: Data) -> [String: Any]? {
        guard let raw = String(data: data, encoding: .ascii)
                     ?? String(data: data, encoding: .isoLatin1) else { return nil }

        guard let startRange = raw.range(of: "<?xml"),
              let endRange = raw.range(of: "</plist>"),
              startRange.upperBound <= endRange.lowerBound else { return nil }

        let xml = String(raw[startRange.lowerBound..<endRange.upperBound])
        guard let xmlData = xml.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(
                  from: xmlData, options: [], format: nil
              ) as? [String: Any] else { return nil }

        return plist
    }
}
