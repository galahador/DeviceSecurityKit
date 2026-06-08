//
//  DSKIntegrityChecker.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
import Darwin
import MachO

internal struct DSKIntegrityChecker {

    private static let logger = SecurityLogger.security(subsystem: "DSKIntegrityChecker")
    private static let checksumQueue = DispatchQueue(label: "com.devicesecuritykit.integrity.checksum")

    // MARK: - Public

    internal static func isDSKCompromised() -> Bool {
        return checkCriticalIMPs() || checkSectionChecksums()
    }

    private static func checkCriticalIMPs() -> Bool {
#if !targetEnvironment(simulator)
        // Get the image path for DSK, use this file's own function as anchor
        let selfPtr = unsafeBitCast(checkCriticalIMPs as () -> Bool, to: UnsafeRawPointer.self)
        var selfInfo = Dl_info()
        guard dladdr(selfPtr, &selfInfo) != 0, let selfImage = selfInfo.dli_fname else {
            logger.warning("DSK integrity: cannot resolve own image — assuming compromised")
            return true
        }
        let dskImagePath = String(cString: selfImage)

        // Resolve key detector entry points and verify they live in the same image as DSK
        let criticalFunctions: [UnsafeRawPointer] = [
            unsafeBitCast(JailbreakDetector.isJailbroken as () -> Bool, to: UnsafeRawPointer.self),
            unsafeBitCast(DebuggerDetector.isDebuggerAttached as () -> Bool, to: UnsafeRawPointer.self),
            unsafeBitCast(FridaDetector.isFridaDetected as (Bool, [UInt16]?) -> Bool, to: UnsafeRawPointer.self),
            unsafeBitCast(HookDetector.isFunctionHooked as () -> Bool, to: UnsafeRawPointer.self),
            unsafeBitCast(SwizzlingDetector.isSwizzled as () -> Bool, to: UnsafeRawPointer.self),
            unsafeBitCast(CertificatePinningDetector.isPinningBypassed as () -> Bool, to: UnsafeRawPointer.self),
            unsafeBitCast(ReverseEngineeringDetector.isReverseEngineered as () -> Bool, to: UnsafeRawPointer.self),
            unsafeBitCast(EmulatorDetector.isEmulator as () -> Bool, to: UnsafeRawPointer.self),
            unsafeBitCast(AttestationDetector.isAttestationFailed as () -> Bool, to: UnsafeRawPointer.self),
            unsafeBitCast(AppIntegrityDetector.isIntegrityCompromised as (String?) -> Bool, to: UnsafeRawPointer.self),
            unsafeBitCast(VPNProxyDetector.isVPNActive as ([String]) -> Bool, to: UnsafeRawPointer.self),
            unsafeBitCast(VPNProxyDetector.isProxyActive as () -> Bool, to: UnsafeRawPointer.self),
            unsafeBitCast(RepackagingDetector.isRepackaged as (String?) -> Bool, to: UnsafeRawPointer.self),
            unsafeBitCast(DylibInjectionDetector.isDylibInjected as () -> Bool, to: UnsafeRawPointer.self),
            unsafeBitCast(ScreenshotDetector.wasScreenshotTaken as () -> Bool, to: UnsafeRawPointer.self),
            unsafeBitCast(ProxyConfigurationChecker.isProxyConfigured as () -> Bool, to: UnsafeRawPointer.self),
        ]

        for funcPtr in criticalFunctions {
            var info = Dl_info()
            guard dladdr(funcPtr, &info) != 0, let fname = info.dli_fname else {
                logger.warning("DSK integrity: cannot resolve image for critical function")
                return true
            }

            let imagePath = String(cString: fname)
            if imagePath != dskImagePath {
                logger.warning("DSK integrity: critical function redirected to \(SecurityLogger.redact(imagePath))")
                return true
            }
        }
#endif
        return false
    }

    /// Sections checksummed at launch and re-verified on each integrity check.
    private static let monitoredSections: [(segment: String, section: String)] = [
        ("__TEXT", "__text"),
        ("__TEXT", "__cstring"),
        ("__TEXT", "__const"),
    ]

    private static var _baselineChecksums: [String: UInt64] = [:]

    internal static func captureBaseline() {
#if !targetEnvironment(simulator)
        var checksums: [String: UInt64] = [:]
        for (segment, section) in monitoredSections {
            if let checksum = computeSectionChecksum(segment: segment, section: section) {
                checksums[sectionKey(segment, section)] = checksum
            }
        }
        checksumQueue.sync { _baselineChecksums = checksums }
#endif
    }

    private static func checkSectionChecksums() -> Bool {
#if !targetEnvironment(simulator)
        let baselines = checksumQueue.sync { _baselineChecksums }
        guard !baselines.isEmpty else { return false }

        for (segment, section) in monitoredSections {
            let key = sectionKey(segment, section)
            guard let baseline = baselines[key] else { continue }

            guard let current = computeSectionChecksum(segment: segment, section: section) else {
                logger.warning("DSK integrity: \(segment),\(section) section vanished — binary has been patched")
                return true
            }

            if current != baseline {
                logger.warning("DSK integrity: \(segment),\(section) section checksum mismatch — binary has been patched")
                return true
            }
        }
#endif
        return false
    }

    private static func sectionKey(_ segment: String, _ section: String) -> String {
        "\(segment),\(section)"
    }

    // FNV-1a 64-bit hash constants.
    private static let fnvOffsetBasis: UInt64 = 0xcbf29ce484222325
    private static let fnvPrime: UInt64 = 0x00000100000001B3

    private static func computeSectionChecksum(segment: String, section: String) -> UInt64? {
#if !targetEnvironment(simulator)
        // Find the Mach-O header for DSK's image
        let selfPtr = unsafeBitCast(computeSectionChecksum as (String, String) -> UInt64?, to: UnsafeRawPointer.self)
        var selfInfo = Dl_info()
        guard dladdr(selfPtr, &selfInfo) != 0, let selfImage = selfInfo.dli_fname else {
            return nil
        }
        let dskImagePath = String(cString: selfImage)

        // Find our image index in the dyld image list
        let imageCount = _dyld_image_count()
        var header: UnsafePointer<mach_header>?
        for i in 0..<imageCount {
            guard let name = _dyld_get_image_name(i) else { continue }
            if String(cString: name) == dskImagePath {
                header = _dyld_get_image_header(i)
                break
            }
        }

        guard let hdr = header else { return nil }

        let hdr64 = UnsafeRawPointer(hdr).assumingMemoryBound(to: mach_header_64.self)
        var size: UInt = 0
        guard let sectionData = getsectiondata(hdr64, segment, section, &size) else { return nil }
        guard size > 0 else { return nil }

        let ptr = UnsafeRawPointer(sectionData)
        let totalSize = Int(size)
        let windowSize = min(4096, totalSize)

        var hash: UInt64 = fnvOffsetBasis

        // Head window
        for i in 0..<windowSize {
            hash ^= UInt64(ptr.load(fromByteOffset: i, as: UInt8.self))
            hash = hash &* fnvPrime
        }

        // Tail window (skip if section is small enough that head already covered it)
        let tailStart = max(windowSize, totalSize - windowSize)
        for i in tailStart..<totalSize {
            hash ^= UInt64(ptr.load(fromByteOffset: i, as: UInt8.self))
            hash = hash &* fnvPrime
        }

        return hash
#else
        return nil
#endif
    }
}
