//
//  AppBundleAnalyzer.swift
//  DSKStaticAnalysis
//

import Foundation
import MachO

public struct AppBundleAnalyzer {

    public enum AnalyzerError: Error, Equatable {
        case bundleNotFound(String)
        case executableNotFound(String)
    }

    public let bundlePath: String
    public let executablePath: String

    public init(bundlePath: String) throws {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: bundlePath, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw AnalyzerError.bundleNotFound(bundlePath)
        }
        self.bundlePath = bundlePath

        guard let infoData = FileManager.default.contents(atPath: bundlePath + "/Info.plist"),
              let info = try? PropertyListSerialization.propertyList(from: infoData, options: [], format: nil) as? [String: Any],
              let executableName = info["CFBundleExecutable"] as? String else {
            throw AnalyzerError.executableNotFound(bundlePath)
        }

        let execPath = bundlePath + "/" + executableName
        guard FileManager.default.fileExists(atPath: execPath) else {
            throw AnalyzerError.executableNotFound(execPath)
        }
        self.executablePath = execPath
    }

    public func hasCodeResourcesFile() -> Bool {
        FileManager.default.fileExists(atPath: bundlePath + "/_CodeSignature/CodeResources")
    }

    // MARK: - Check 2: CodeResources file hashes

    private var codeResources: [String: Any]? {
        let path = bundlePath + "/_CodeSignature/CodeResources"
        guard let data = FileManager.default.contents(atPath: path),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            return nil
        }
        return plist
    }

    /// Returns the relative paths of files whose on-disk SHA-256 doesn't match the hash recorded in _CodeSignature/CodeResources
    public func codeResourcesHashMismatches(criticalFiles: [String]? = nil) -> [String] {
        guard let plist = codeResources,
              let files2 = plist["files2"] as? [String: Any] else {
            return []
        }

        var mismatches: [String] = []
        for relativePath in (criticalFiles ?? defaultCriticalFiles()) {
            guard let entry = files2[relativePath] as? [String: Any],
                  let hashData = entry["hash2"] as? Data else {
                continue
            }

            let fullPath = bundlePath + "/" + relativePath
            guard let fileData = FileManager.default.contents(atPath: fullPath) else {
                continue
            }

            if MachOCodeSignature.sha256(fileData) != hashData {
                mismatches.append(relativePath)
            }
        }
        return mismatches
    }

    /// Info.plist, the main executable, and every embedded framework's Info.plist + binary.
    public func defaultCriticalFiles() -> [String] {
        var files = ["Info.plist", (executablePath as NSString).lastPathComponent]

        let frameworksPath = bundlePath + "/Frameworks"
        if let frameworks = try? FileManager.default.contentsOfDirectory(atPath: frameworksPath) {
            for fw in frameworks where fw.hasSuffix(".framework") {
                files.append("Frameworks/\(fw)/Info.plist")
                let binaryName = (fw as NSString).deletingPathExtension
                files.append("Frameworks/\(fw)/\(binaryName)")
            }
        }

        return files
    }

    public func hasMachOCodeSignature() -> Bool {
        guard let data = FileManager.default.contents(atPath: executablePath) else { return false }
        return MachOCodeSignature.hasCodeSignatureLoadCommand(data)
    }

    // MARK: - Leaf signing certificate

    public func leafCertificateSHA256Hex() -> String? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: executablePath), options: .mappedIfSafe) else {
            return nil
        }
        return MachOCodeSignature.leafCertificateSHA256Hex(executableData: data)
    }

    // MARK: - Provisioning profile

    public func provisioningProfile() -> [String: Any]? {
        let path = bundlePath + "/embedded.mobileprovision"
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return Self.extractPlist(from: data)
    }

    // MARK: - Plist extraction (XML or binary, embedded in CMS envelope)

    private static let xmlStartMarker = Data("<?xml".utf8)
    private static let xmlEndMarker   = Data("</plist>".utf8)
    private static let bplistMagic    = Data("bplist00".utf8)

    public static func extractPlist(from data: Data) -> [String: Any]? {
        if let result = extractXMLPlist(from: data) {
            return result
        }
        return extractBinaryPlist(from: data)
    }

    private static func extractXMLPlist(from data: Data) -> [String: Any]? {
        var searchStart = data.startIndex

        while let startIdx = data.range(of: xmlStartMarker, in: searchStart..<data.endIndex)?.lowerBound {
            guard let endRange = data.range(of: xmlEndMarker, options: .backwards, in: startIdx..<data.endIndex) else {
                searchStart = data.index(after: startIdx)
                continue
            }

            let plistSlice = data[startIdx..<endRange.upperBound]
            if let plist = try? PropertyListSerialization.propertyList(from: Data(plistSlice), options: [], format: nil) as? [String: Any] {
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
            if let plist = try? PropertyListSerialization.propertyList(from: Data(remaining), options: [], format: nil) as? [String: Any] {
                return plist
            }

            searchStart = data.index(after: startIdx)
        }

        return nil
    }
}
