//
//  main.swift
//  dsk-scan
//
//  CLI tool that runs DSK's static analysis checks (code signature presence,
//  CodeResources hashes, Mach-O LC_CODE_SIGNATURE, provisioning profile,
//  leaf signing certificate) against a built .ipa or .app, for use in CI
//  pre-submission gates.
//

import Foundation
import DSKStaticAnalysis

struct CLIOptions {
    var inputPath: String?
    var expectedCertificateHash: String?
    var expectedTeamID: String?
}

func printUsage() {
    print("""
    dsk-scan — static security checks for a built .ipa or .app (CI pre-submission gate)

    Usage:
      dsk-scan <path-to.ipa-or-.app> [options]

    Options:
      --expected-certificate-hash <hex>   Fail if the leaf signing certificate's SHA-256 doesn't match
      --expected-team-id <id>              Fail if the provisioning profile's TeamIdentifier doesn't match
      -h, --help                            Show this help message
    """)
}

enum ParseResult {
    case options(CLIOptions)
    case help
    case error
}

func parseArguments(_ arguments: [String]) -> ParseResult {
    var options = CLIOptions()
    var args = arguments[1...].makeIterator()

    while let arg = args.next() {
        switch arg {
        case "-h", "--help":
            return .help
        case "--expected-certificate-hash":
            options.expectedCertificateHash = args.next()
        case "--expected-team-id":
            options.expectedTeamID = args.next()
        default:
            if options.inputPath == nil {
                options.inputPath = arg
            } else {
                FileHandle.standardError.write("Unexpected argument: \(arg)\n".data(using: .utf8)!)
                return .error
            }
        }
    }

    guard options.inputPath != nil else { return .error }
    return .options(options)
}

/// Extracts an `.ipa` to a temporary directory and returns the path to `Payload/*.app`.
/// dsk-scan is a macOS/CI tool — `Process` (used to invoke `/usr/bin/unzip`) isn't available on iOS,
/// which is otherwise part of this package's platform set.
#if os(macOS)
func extractIPA(at path: String) throws -> String {
    let tempDir = FileManager.default.temporaryDirectory
        .appendingPathComponent("dsk-scan-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
    process.arguments = ["-q", path, "-d", tempDir.path]

    try process.run()
    process.waitUntilExit()

    guard process.terminationStatus == 0 else {
        throw CLIError.extractionFailed(path)
    }

    let payloadDir = tempDir.appendingPathComponent("Payload")
    guard let appName = try FileManager.default.contentsOfDirectory(atPath: payloadDir.path)
        .first(where: { $0.hasSuffix(".app") }) else {
        throw CLIError.appBundleNotFound(path)
    }

    return payloadDir.appendingPathComponent(appName).path
}
#else
func extractIPA(at path: String) throws -> String {
    throw CLIError.extractionFailed(path)
}
#endif

enum CLIError: Error, CustomStringConvertible {
    case extractionFailed(String)
    case appBundleNotFound(String)

    var description: String {
        switch self {
        case .extractionFailed(let path):
            return "Failed to extract .ipa at \(path)"
        case .appBundleNotFound(let path):
            return "No Payload/*.app found inside \(path)"
        }
    }
}

struct CheckResult {
    let name: String
    let passed: Bool
    let detail: String?
}

func runChecks(bundlePath: String, options: CLIOptions) -> [CheckResult] {
    var results: [CheckResult] = []

    guard let analyzer = try? AppBundleAnalyzer(bundlePath: bundlePath) else {
        results.append(CheckResult(name: "bundle", passed: false, detail: "Could not load app bundle at \(bundlePath)"))
        return results
    }

    let hasCodeResources = analyzer.hasCodeResourcesFile()
    results.append(CheckResult(
        name: "CodeResources presence",
        passed: hasCodeResources,
        detail: hasCodeResources ? nil : "_CodeSignature/CodeResources not found"
    ))

    let mismatches = analyzer.codeResourcesHashMismatches()
    results.append(CheckResult(
        name: "CodeResources hashes",
        passed: mismatches.isEmpty,
        detail: mismatches.isEmpty ? nil : "Modified files: \(mismatches.joined(separator: ", "))"
    ))

    let hasSignature = analyzer.hasMachOCodeSignature()
    results.append(CheckResult(
        name: "Mach-O LC_CODE_SIGNATURE",
        passed: hasSignature,
        detail: hasSignature ? nil : "LC_CODE_SIGNATURE load command missing"
    ))

    let leafHash = analyzer.leafCertificateSHA256Hex()
    if let expected = options.expectedCertificateHash {
        let passed = leafHash?.lowercased() == expected.lowercased()
        results.append(CheckResult(
            name: "Signing certificate hash",
            passed: passed,
            detail: passed ? nil : "Expected \(expected.lowercased()), found \(leafHash ?? "none")"
        ))
    } else {
        results.append(CheckResult(
            name: "Signing certificate hash",
            passed: true,
            detail: leafHash.map { "Current hash: \($0)" } ?? "Could not extract leaf certificate"
        ))
    }

    if let expectedTeamID = options.expectedTeamID {
        let profile = analyzer.provisioningProfile()
        let teamIDs = profile?["TeamIdentifier"] as? [String] ?? []
        let passed = teamIDs.contains(expectedTeamID)
        results.append(CheckResult(
            name: "Provisioning profile team ID",
            passed: passed,
            detail: passed ? nil : "Expected \(expectedTeamID), found \(teamIDs.joined(separator: ", "))"
        ))
    }

    return results
}

// MARK: - Entry point

let options: CLIOptions
switch parseArguments(CommandLine.arguments) {
case .options(let parsed):
    options = parsed
case .help:
    printUsage()
    exit(0)
case .error:
    printUsage()
    exit(1)
}

let inputPath = options.inputPath!

var bundlePath = inputPath
var cleanupDir: URL?

if inputPath.hasSuffix(".ipa") {
    do {
        bundlePath = try extractIPA(at: inputPath)
        cleanupDir = URL(fileURLWithPath: bundlePath).deletingLastPathComponent().deletingLastPathComponent()
    } catch {
        FileHandle.standardError.write("Error: \(error)\n".data(using: .utf8)!)
        exit(1)
    }
}

let results = runChecks(bundlePath: bundlePath, options: options)

if let cleanupDir {
    try? FileManager.default.removeItem(at: cleanupDir)
}

print("dsk-scan report for \(inputPath)")
print(String(repeating: "-", count: 40))

var allPassed = true
for result in results {
    let status = result.passed ? "PASS" : "FAIL"
    print("[\(status)] \(result.name)")
    if let detail = result.detail {
        print("       \(detail)")
    }
    if !result.passed {
        allPassed = false
    }
}

print(String(repeating: "-", count: 40))
print(allPassed ? "Result: PASS" : "Result: FAIL")

exit(allPassed ? 0 : 1)
