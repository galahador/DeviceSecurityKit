//
//  AppIntegrityDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
import CommonCrypto
import MachO

public final class AppIntegrityDetector {

    private static let logger = SecurityLogger.security(subsystem: "AppIntegrityDetector")

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
        let path = Bundle.main.bundlePath + "/_CodeSignature/CodeResources"
        guard FileManager.default.fileExists(atPath: path) else {
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
        let bundlePath = Bundle.main.bundlePath
        let codeResourcesPath = bundlePath + "/_CodeSignature/CodeResources"

        guard let data = FileManager.default.contents(atPath: codeResourcesPath),
              let plist = try? PropertyListSerialization.propertyList(
                  from: data, options: [], format: nil
              ) as? [String: Any] else {
            return false // presence check already handles missing file
        }

        // CodeResources has "files2" dict with SHA256 hashes
        guard let files2 = plist["files2"] as? [String: Any] else {
            logger.warning("CodeResources missing files2 dictionary — possible tampering")
            return true
        }

        // Validate critical files: Info.plist and the main executable
        let criticalFiles = buildCriticalFileList()

        for relativePath in criticalFiles {
            guard let entry = files2[relativePath] as? [String: Any],
                  let hashData = entry["hash2"] as? Data else {
                continue // file not in CodeResources — skip (may not be present)
            }

            let fullPath = bundlePath + "/" + relativePath
            guard let fileData = FileManager.default.contents(atPath: fullPath) else {
                continue
            }

            let computedHash = sha256(fileData)
            if computedHash != hashData {
                logger.warning("Hash mismatch for \(SecurityLogger.redact(relativePath)) — file has been modified")
                return true
            }
        }

        return false
#endif
    }

    // MARK: - Check 3: Mach-O LC_CODE_SIGNATURE load command

    private static func checkMachOCodeSignature() -> Bool {
#if targetEnvironment(simulator)
        return false
#else
        guard let executablePath = Bundle.main.executablePath,
              let executableData = FileManager.default.contents(atPath: executablePath) else {
            return false
        }

        return executableData.withUnsafeBytes { rawBuffer -> Bool in
            guard rawBuffer.count >= MemoryLayout<mach_header_64>.size else { return true }

            let header = rawBuffer.load(as: mach_header_64.self)

            // Verify this is a valid 64-bit Mach-O
            guard header.magic == MH_MAGIC_64 else { return true }

            var offset = MemoryLayout<mach_header_64>.size

            for _ in 0..<header.ncmds {
                guard offset + MemoryLayout<load_command>.size <= rawBuffer.count else { break }

                let cmd = rawBuffer.load(fromByteOffset: offset, as: load_command.self)

                if cmd.cmd == LC_CODE_SIGNATURE {
                    return false // signature found not compromised
                }

                offset += Int(cmd.cmdsize)
            }

            logger.warning("LC_CODE_SIGNATURE load command missing — binary may be re-signed or stripped")
            return true
        }
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

    // MARK: - Helpers

    private static func sha256(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { buffer in
            _ = CC_SHA256(buffer.baseAddress, CC_LONG(buffer.count), &hash)
        }
        return Data(hash)
    }

    private static func buildCriticalFileList() -> [String] {
        var files = ["Info.plist"]
        // Add embedded frameworks' Info.plist entries
        let frameworksPath = Bundle.main.bundlePath + "/Frameworks"
        if let frameworks = try? FileManager.default.contentsOfDirectory(atPath: frameworksPath) {
            for fw in frameworks where fw.hasSuffix(".framework") {
                files.append("Frameworks/\(fw)/Info.plist")
            }
        }
        return files
    }

    private static func extractPlist(from data: Data) -> [String: Any]? {
        if let result = extractXMLPlist(from: data) {
            return result
        }
        if let result = extractBinaryPlist(from: data) {
            return result
        }
        return nil
    }

    private static let xmlStartMarker = Data("<?xml".utf8)
    private static let xmlEndMarker   = Data("</plist>".utf8)
    private static let bplistMagic    = Data("bplist00".utf8)

    private static func extractXMLPlist(from data: Data) -> [String: Any]? {
        var searchStart = data.startIndex

        while let startIdx = data.range(of: xmlStartMarker, in: searchStart..<data.endIndex)?.lowerBound {
            // Find the LAST </plist> after this <?xml to handle nested XML correctly
            guard let endRange = data.range(of: xmlEndMarker, options: .backwards,
                                            in: startIdx..<data.endIndex) else {
                searchStart = data.index(after: startIdx)
                continue
            }

            let plistSlice = data[startIdx..<endRange.upperBound]
            if let plist = try? PropertyListSerialization.propertyList(
                from: Data(plistSlice), options: [], format: nil
            ) as? [String: Any] {
                return plist
            }

            searchStart = data.index(after: startIdx)
        }

        return nil
    }

    private static func extractBinaryPlist(from data: Data) -> [String: Any]? {
        var searchStart = data.startIndex

        while let startIdx = data.range(of: bplistMagic, in: searchStart..<data.endIndex)?.lowerBound {
            let remaining = data[startIdx..<data.endIndex]
            if let plist = try? PropertyListSerialization.propertyList(
                from: Data(remaining), options: [], format: nil
            ) as? [String: Any] {
                return plist
            }

            searchStart = data.index(after: startIdx)
        }

        return nil
    }
}
