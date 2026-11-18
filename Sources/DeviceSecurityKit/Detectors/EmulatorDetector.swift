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

    private struct Constants {
        static let loggerSubsystem = "DeviceSecurityKit"
        static let cacheQueueLabel = "com.devicesecuritykit.emulator.cache"

        static let methodCompilationTarget = "targetEnvironment(simulator)"
        static let methodSimulatorPaths = "simulatorPaths"
        static let methodDeviceModel = "deviceModel"
        static let methodSystemProperties = "systemProperties"
        static let methodRuntimeEnvironment = "runtimeEnvironment"
        static let methodProcessEnvironment = "processEnvironment"
        static let methodHardwareMismatch = "hardwareIdentifierMismatch"
        static let methodDeviceCheck = "deviceCheckUnsupported"
        static let methodSeparator = ", "

        static let publicDetected = "Emulator detected"
        static let publicNotDetected = "No emulator detected. Running on physical iOS device."
        static let debugPlaceholder = "/"
        static let debugViaCompilationTarget = "Emulator detected via compilation target"
        static let debugViaPaths = "Emulator detected via filesystem paths"
        static let debugViaModel = "Emulator detected via device model"
        static let debugViaProperties = "Emulator detected via system properties"
        static let debugViaRuntime = "Emulator detected via runtime environment"
        static let debugViaProcess = "Emulator detected via process environment"
        static let debugViaHardware = "Emulator detected via hw.machine vs uname mismatch"
        static let debugViaDeviceCheck = "Emulator detected via DeviceCheck unavailability"

        static let bridgePath = "/System/Library/CoreServices/CoreSimulatorBridge.app"
        static let frameworkPath = "/System/Library/PrivateFrameworks/CoreSimulator.framework"
        static let developerPath = "/Library/Developer/CoreSimulator"
        static let coreSimulatorMarker = "/CoreSimulator/"

        static let archI386 = "i386"
        static let archX86_64 = "x86_64"
        static let simulatorLowercase = "simulator"
        static let simulatorCapitalized = "Simulator"
        static let arm64 = "arm64"

        static let envDeviceName = "SIMULATOR_DEVICE_NAME"
        static let envVersionInfo = "SIMULATOR_VERSION_INFO"

        static let realityDevicePrefix = "RealityDevice"
        static let unknownModel = "Unknown"

        static let simulatorEnvDebugger = "Debugger attachment detected in simulator environment"
        static let realDeviceDebugger = "Debugger detected but appears to be real device debugging"
        static let deviceCheckUnsupportedLog = "DeviceCheck not supported — likely simulator"

        static func detectedWithConfidence(_ confidence: Float, _ methods: [String]) -> String {
            "Emulator detected with confidence: \(String(format: "%.2f", confidence * 100))%. Methods: \(methods.joined(separator: methodSeparator))"
        }
        static func criticalPathFound(_ path: String) -> String {
            "Found critical emulator-specific path: \(path)"
        }
        static func additionalPathFound(_ path: String) -> String {
            "Found additional simulator path: \(path)"
        }
        static func simulatorArchitecture(_ model: String) -> String {
            "Detected simulator-only architecture: \(model)"
        }
        static func simulatorInModel(_ model: String) -> String {
            "Found 'Simulator' in model identifier: \(model)"
        }
        static func simulatorEnvVar(_ name: String) -> String {
            "Found simulator environment variable: \(name)"
        }
        static func simulatorArgument(_ argument: String) -> String {
            "Found simulator-specific argument: \(argument)"
        }
        static func simulatorBundlePath(_ path: String) -> String {
            "Bundle path indicates simulator: \(path)"
        }
        static func nonIOSMachine(_ machine: String) -> String {
            "hw.machine returned non-iOS device identifier: \(machine)"
        }
    }

    // MARK: - Public
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

    public static var minimumDetectionMethods: Int = 2
    
    // MARK: - Private Properties
    private static let logger = SecurityLogger.detection(subsystem: Constants.loggerSubsystem)
    private static let emulatorDetectorListOptions = EmulatorDetectorListOptions()
    private static var cachedDeviceModel: String?
    private static let cacheQueue = DispatchQueue(label: Constants.cacheQueueLabel, attributes: .concurrent)

    // MARK: - Public Methods
    public static func isEmulator() -> Bool {
        let result = detectEmulator()
        return result.isEmulator
    }

    public static func detectEmulator() -> DetectionResult {

        if checkSimulatorEnvironment() {
            secureLog(publicMessage: Constants.publicDetected,
                      debugMessage: Constants.debugViaCompilationTarget, logger: logger)
            return DetectionResult(
                isEmulator: true,
                detectionMethods: [Constants.methodCompilationTarget],
                confidence: 1.0
            )
        }

        var detectionMethods: [String] = []
        var confidenceScore: Float = 0.0
        let maxConfidenceScore: Float = 10.5

        if checkSimulatorPaths() {
            detectionMethods.append(Constants.methodSimulatorPaths)
            confidenceScore += 1.5
            secureLog(publicMessage: Constants.publicDetected,
                      debugMessage: Constants.debugViaPaths, logger: logger)
        }

        if checkDeviceModel() {
            detectionMethods.append(Constants.methodDeviceModel)
            confidenceScore += 1.5
            secureLog(publicMessage: Constants.publicDetected,
                      debugMessage: Constants.debugViaModel, logger: logger)
        }

        if checkSystemProperties() {
            detectionMethods.append(Constants.methodSystemProperties)
            confidenceScore += 2.0
            secureLog(publicMessage: Constants.publicDetected,
                      debugMessage: Constants.debugViaProperties, logger: logger)
        }

        if checkRuntimeEnvironment() {
            detectionMethods.append(Constants.methodRuntimeEnvironment)
            confidenceScore += 0.8
            secureLog(publicMessage: Constants.publicDetected,
                      debugMessage: Constants.debugViaRuntime, logger: logger)
        }

        if checkProcessEnvironment() {
            detectionMethods.append(Constants.methodProcessEnvironment)
            confidenceScore += 1.2
            secureLog(publicMessage: Constants.publicDetected,
                      debugMessage: Constants.debugViaProcess, logger: logger)
        }

        if checkHardwareIdentifierMismatch() {
            detectionMethods.append(Constants.methodHardwareMismatch)
            confidenceScore += 2.0
            secureLog(publicMessage: Constants.publicDetected,
                      debugMessage: Constants.debugViaHardware, logger: logger)
        }

        if checkDeviceCheckUnsupported() {
            detectionMethods.append(Constants.methodDeviceCheck)
            confidenceScore += 1.5
            secureLog(publicMessage: Constants.publicDetected,
                      debugMessage: Constants.debugViaDeviceCheck, logger: logger)
        }

        let confidence = min(confidenceScore / maxConfidenceScore, 1.0)
        let isEmulator = detectionMethods.count >= minimumDetectionMethods

        let result = DetectionResult(
            isEmulator: isEmulator,
            detectionMethods: detectionMethods,
            confidence: confidence
        )

        if isEmulator {
            secureLog(publicMessage: Constants.detectedWithConfidence(confidence, detectionMethods),
                      debugMessage: Constants.publicDetected, logger: logger)
        } else {
            secureLog(publicMessage: Constants.publicNotDetected,
                      debugMessage: Constants.debugPlaceholder, logger: logger)
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
            Constants.bridgePath,
            Constants.frameworkPath,
            Constants.developerPath
        ]

        for path in criticalPaths {
            if FileManager.default.fileExists(atPath: path) {
                logger.debug(Constants.criticalPathFound(SecurityLogger.redact(path)))
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
                logger.debug(Constants.additionalPathFound(SecurityLogger.redact(path)))
            }
        }

        return additionalMatches >= 2
    }

    private static func checkDeviceModel() -> Bool {
        let modelIdentifier = getDeviceModelIdentifier()

        let simulatorOnlyIdentifiers = [
            Constants.archI386,
            Constants.archX86_64
        ]

        for identifier in simulatorOnlyIdentifiers {
            if modelIdentifier.lowercased() == identifier.lowercased() {
                logger.debug(Constants.simulatorArchitecture(SecurityLogger.redact(modelIdentifier)))
                return true
            }
        }

        if modelIdentifier.lowercased().contains(Constants.simulatorLowercase) {
            logger.debug(Constants.simulatorInModel(SecurityLogger.redact(modelIdentifier)))
            return true
        }

        if modelIdentifier.lowercased().contains(Constants.arm64) {
            return checkIfSimulatorOnAppleSilicon()
        }

        return false
    }

    private static let o = StringObfuscator.shared

    private static func checkIfSimulatorOnAppleSilicon() -> Bool {
        let processName = ProcessInfo.processInfo.processName
        let environment = ProcessInfo.processInfo.environment

        if environment[Constants.envDeviceName] != nil ||
            environment[Constants.envVersionInfo] != nil ||
            environment[o.reveal([0xDE, 0x8D, 0x7B, 0x6D, 0x03, 0x36, 0x6B, 0x12, 0x16, 0x34, 0xA5, 0xEE, 0xCA, 0xC8, 0x02, 0xED, 0x39, 0x63])] != nil {
            return true
        }

        if processName.contains(Constants.simulatorCapitalized) || processName.contains(Constants.simulatorLowercase) {
            return true
        }

        return false
    }

    private static func checkSystemProperties() -> Bool {

        for envVar in EmulatorDetector.emulatorDetectorListOptions.suspiciousEnvVars {
            if getenv(envVar) != nil {
                logger.debug(Constants.simulatorEnvVar(SecurityLogger.redact(envVar)))
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
                let hasSimulatorEnv = environment[Constants.envDeviceName] != nil ||
                environment[Constants.envVersionInfo] != nil

                if hasSimulatorEnv {
                    logger.debug(Constants.simulatorEnvDebugger)
                    return true
                }
                logger.debug(Constants.realDeviceDebugger)
            }
        }

        return false
    }

    private static func checkProcessEnvironment() -> Bool {
        let arguments = ProcessInfo.processInfo.arguments



        for argument in arguments {
            if argument.contains(Constants.coreSimulatorMarker) {
                logger.debug(Constants.simulatorArgument(SecurityLogger.redact(argument)))
                return true
            }
        }

        let bundlePath = Bundle.main.bundlePath
        if bundlePath.contains(Constants.coreSimulatorMarker) {
            logger.debug(Constants.simulatorBundlePath(SecurityLogger.redact(bundlePath)))
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

        if !isRealDevice && !isCompatibilityHost(sysctlMachine) {
            logger.debug(Constants.nonIOSMachine(SecurityLogger.redact(sysctlMachine)))
            return true
        }

        return false
    }

    private static func isCompatibilityHost(_ machine: String) -> Bool {
        ProcessInfo.processInfo.isiOSAppOnMac || machine.hasPrefix(Constants.realityDevicePrefix)
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
            if !DCDevice.current.isSupported, !ProcessInfo.processInfo.isiOSAppOnMac {
                logger.debug(Constants.deviceCheckUnsupportedLog)
                return true
            }
        }
        return false
    }

    // MARK: - Helper Methods
    private static func getDeviceModelIdentifier() -> String {
        return cacheQueue.sync(flags: .barrier) {
            if let cached = cachedDeviceModel {
                return cached
            }

            var systemInfo = utsname()
            uname(&systemInfo)
            let identifier = withUnsafePointer(to: &systemInfo.machine) {
                $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                    String(validatingUTF8: $0) ?? Constants.unknownModel
                }
            }

            cachedDeviceModel = identifier
            return identifier
        }
    }
}
