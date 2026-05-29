//
//  EmulatorDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
import Darwin
import DeviceCheck

public final class EmulatorDetector {

    // MARK: - Public Types

    public struct DetectionResult {
        public let isEmulator: Bool
        public let detectionMethods: [String]
        public let confidence: Float
        public let timestamp: Date

        public init(isEmulator: Bool, detectionMethods: [String], confidence: Float) {
            self.isEmulator = isEmulator
            self.detectionMethods = detectionMethods
            self.confidence = confidence
            self.timestamp = Date()
        }
    }

    // MARK: - Private Properties

    private static let logger = SecurityLogger.detection(subsystem: "DeviceSecurityKit")
    private static let emulatorDetectorListOptions = EmulatorDetectorListOptions()

    private static var cachedDeviceModel: String?
    private static let cacheQueue = DispatchQueue(label: "com.devicesecuritykit.emulator.cache", attributes: .concurrent)

    // MARK: - Public Methods

    public static func isEmulator() -> Bool {
        let result = detectEmulator()
        return result.isEmulator
    }

    public static func detectEmulator() -> DetectionResult {

        if checkSimulatorEnvironment() {
            secureLog(publicMessage: "Emulator detected",
                      debugMessage: "Emulator detected via compilation target", logger: logger)
            return DetectionResult(
                isEmulator: true,
                detectionMethods: ["targetEnvironment(simulator)"],
                confidence: 1.0
            )
        }

        // Runtime checks — require >= 2 signals to reduce false positives on real devices
        var detectionMethods: [String] = []
        var confidenceScore: Float = 0.0
        let maxConfidenceScore: Float = 10.5

        if checkSimulatorPaths() {
            detectionMethods.append("simulatorPaths")
            confidenceScore += 1.5
            secureLog(publicMessage: "Emulator detected",
                      debugMessage: "Emulator detected via filesystem paths", logger: logger)
        }

        if checkDeviceModel() {
            detectionMethods.append("deviceModel")
            confidenceScore += 1.5
            secureLog(publicMessage: "Emulator detected",
                      debugMessage: "Emulator detected via device model", logger: logger)
        }

        if checkSystemProperties() {
            detectionMethods.append("systemProperties")
            confidenceScore += 2.0
            secureLog(publicMessage: "Emulator detected",
                      debugMessage: "Emulator detected via system properties", logger: logger)
        }

        if checkRuntimeEnvironment() {
            detectionMethods.append("runtimeEnvironment")
            confidenceScore += 0.8
            secureLog(publicMessage: "Emulator detected",
                      debugMessage: "Emulator detected via runtime environment", logger: logger)
        }

        if checkProcessEnvironment() {
            detectionMethods.append("processEnvironment")
            confidenceScore += 1.2
            secureLog(publicMessage: "Emulator detected",
                      debugMessage: "Emulator detected via process environment", logger: logger)
        }

        if checkHardwareIdentifierMismatch() {
            detectionMethods.append("hardwareIdentifierMismatch")
            confidenceScore += 2.0
            secureLog(publicMessage: "Emulator detected",
                      debugMessage: "Emulator detected via hw.machine vs uname mismatch", logger: logger)
        }

        if checkDeviceCheckUnsupported() {
            detectionMethods.append("deviceCheckUnsupported")
            confidenceScore += 1.5
            secureLog(publicMessage: "Emulator detected",
                      debugMessage: "Emulator detected via DeviceCheck unavailability", logger: logger)
        }

        let confidence = min(confidenceScore / maxConfidenceScore, 1.0)
        let isEmulator = detectionMethods.count >= 2

        let result = DetectionResult(
            isEmulator: isEmulator,
            detectionMethods: detectionMethods,
            confidence: confidence
        )

        if isEmulator {
            secureLog(publicMessage: "Emulator detected with confidence: \(String(format: "%.2f", confidence * 100))%. Methods: \(detectionMethods.joined(separator: ", "))",
                      debugMessage: "Emulator detected", logger: logger)
        } else {
            secureLog(publicMessage: "No emulator detected. Running on physical iOS device.",
                      debugMessage: "/", logger: logger)
        }

        return result
    }

    private static func secureLog(publicMessage: String, debugMessage: String, logger: SecurityLogger) {
#if DEBUG
        logger.error(debugMessage)
#else
        logger.info(publicMessage)
#endif
    }

    // MARK: - Private Detection Methods

    private static func checkSimulatorEnvironment() -> Bool {
#if targetEnvironment(simulator)
        return true
#else
        return false
#endif
    }

    private static func checkSimulatorPaths() -> Bool {
        let criticalPaths = [
            "/System/Library/CoreServices/CoreSimulatorBridge.app",
            "/System/Library/PrivateFrameworks/CoreSimulator.framework",
            "/Library/Developer/CoreSimulator"
        ]

        for path in criticalPaths {
            if FileManager.default.fileExists(atPath: path) {
                logger.debug("Found critical emulator-specific path: \(path)")
                return true
            }
        }

        let additionalPaths = emulatorDetectorListOptions.simulatorPaths.filter {
            !criticalPaths.contains($0)
        }

        var additionalMatches = 0
        for path in additionalPaths {
            if FileManager.default.fileExists(atPath: path) {
                additionalMatches += 1
                logger.debug("Found additional simulator path: \(path)")
            }
        }

        return additionalMatches >= 2
    }

    private static func checkDeviceModel() -> Bool {
        let modelIdentifier = getDeviceModelIdentifier()

        let simulatorOnlyIdentifiers = [
            "i386",
            "x86_64"
        ]

        for identifier in simulatorOnlyIdentifiers {
            if modelIdentifier.lowercased() == identifier.lowercased() {
                logger.debug("Detected simulator-only architecture: \(modelIdentifier)")
                return true
            }
        }

        if modelIdentifier.lowercased().contains("simulator") {
            logger.debug("Found 'Simulator' in model identifier: \(modelIdentifier)")
            return true
        }

        if modelIdentifier.lowercased().contains("arm64") {
            return checkIfSimulatorOnAppleSilicon()
        }

        return false
    }

    private static let o = StringObfuscator.shared

    private static func checkIfSimulatorOnAppleSilicon() -> Bool {
        let processName = ProcessInfo.processInfo.processName
        let environment = ProcessInfo.processInfo.environment

        if environment["SIMULATOR_DEVICE_NAME"] != nil ||
            environment["SIMULATOR_VERSION_INFO"] != nil ||
            environment[o.reveal([0xDE, 0x8D, 0x7B, 0x6D, 0x03, 0x36, 0x6B, 0x12, 0x16, 0x34, 0xA5, 0xEE, 0xCA, 0xC8, 0x02, 0xED, 0x39, 0x63])] != nil {
            return true
        }

        if processName.contains("Simulator") || processName.contains("simulator") {
            return true
        }

        return false
    }

    private static func checkSystemProperties() -> Bool {

        for envVar in EmulatorDetector.emulatorDetectorListOptions.suspiciousEnvVars {
            if let value = getenv(envVar) {
                logger.debug("Found simulator environment variable: \(envVar) = \(String(cString: value))")
                return true
            }
        }

        return false
    }

    private static func checkRuntimeEnvironment() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]

        let result = mib.withUnsafeMutableBufferPointer { mibPtr in
            sysctl(mibPtr.baseAddress, 4, &info, &size, nil, 0)
        }

        if result == 0 {
            let isDebuggerAttached = (info.kp_proc.p_flag & P_TRACED) != 0

            if isDebuggerAttached {
                let environment = ProcessInfo.processInfo.environment
                let hasSimulatorEnv = environment["SIMULATOR_DEVICE_NAME"] != nil ||
                environment["SIMULATOR_VERSION_INFO"] != nil

                if hasSimulatorEnv {
                    logger.debug("Debugger attachment detected in simulator environment")
                    return true
                }
                logger.debug("Debugger detected but appears to be real device debugging")
            }
        }

        return false
    }

    private static func checkProcessEnvironment() -> Bool {
        let processName = ProcessInfo.processInfo.processName
        let arguments = ProcessInfo.processInfo.arguments

        if processName.lowercased().contains("simulator") {
            logger.debug("Process name contains 'simulator': \(processName)")
            return true
        }

        for argument in arguments {
            if argument.contains("Simulator") || argument.contains("/CoreSimulator/") {
                logger.debug("Found simulator-specific argument: \(argument)")
                return true
            }
        }

        let bundlePath = Bundle.main.bundlePath
        if bundlePath.contains("CoreSimulator") || bundlePath.contains("Simulator") {
            logger.debug("Bundle path indicates simulator: \(bundlePath)")
            return true
        }

        return false
    }

    // MARK: - Hardware Identifier Cross-Reference

    private static func checkHardwareIdentifierMismatch() -> Bool {
        let sysctlMachine = getSysctlString(o.reveal([0xD6, 0x74, 0x93, 0xE5, 0xD7, 0x68, 0x0F, 0x3A, 0xD8, 0x86, 0x18, 0x68, 0xB9, 0x10]))
        guard !sysctlMachine.isEmpty else { return false }

        let iphonePrefix = o.reveal([0x07, 0x1B, 0x11, 0x03, 0xAD, 0x2C, 0x36, 0x67, 0xF4, 0x93])
        let ipadPrefix = o.reveal([0x62, 0xE0, 0x9E, 0x6E, 0xCF, 0xE4, 0x35, 0x88])
        let ipodPrefix = o.reveal([0xF6, 0xEA, 0xD1, 0xE6, 0x51, 0x3D, 0x43, 0xDD])

        let isRealDevice = sysctlMachine.hasPrefix(iphonePrefix)
            || sysctlMachine.hasPrefix(ipadPrefix)
            || sysctlMachine.hasPrefix(ipodPrefix)

        if !isRealDevice {
            logger.debug("hw.machine returned '\(sysctlMachine)' — not an iOS device identifier")
            return true
        }

        return false
    }

    private static func getSysctlString(_ name: String) -> String {
        var size: Int = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return "" }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return "" }
        return String(cString: buffer)
    }

    // MARK: - DeviceCheck Availability

    private static func checkDeviceCheckUnsupported() -> Bool {
        if #available(iOS 11.0, *) {
            if !DCDevice.current.isSupported {
                logger.debug("DeviceCheck not supported — likely simulator")
                return true
            }
        }
        return false
    }

    // MARK: - Helper Methods

    private static func getDeviceModelIdentifier() -> String {
        if let cached = cacheQueue.sync(execute: { cachedDeviceModel }) {
            return cached
        }

        return cacheQueue.sync(flags: .barrier) {
            if let cached = cachedDeviceModel {
                return cached
            }

            var systemInfo = utsname()
            uname(&systemInfo)
            let identifier = withUnsafePointer(to: &systemInfo.machine) {
                $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                    String(validatingUTF8: $0) ?? "Unknown"
                }
            }

            cachedDeviceModel = identifier
            return identifier
        }
    }
}
