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
        return checkCriticalIMPs() || checkTextSegmentChecksum()
    }

    // MARK: - Check 1: Verify DSK's own critical functions haven't been redirected

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

    // MARK: - Check 2: Checksum DSK's own __TEXT segment (FNV-1a, full section)

    private static var _baselineChecksum: UInt64?

    internal static func captureBaseline() {
#if !targetEnvironment(simulator)
        guard let checksum = computeTextChecksum() else { return }
        checksumQueue.sync { _baselineChecksum = checksum }
#endif
    }

    private static func checkTextSegmentChecksum() -> Bool {
#if !targetEnvironment(simulator)
        let baseline = checksumQueue.sync { _baselineChecksum }
        guard let baseline else { return false }
        guard let current = computeTextChecksum() else { return true }

        if current != baseline {
            logger.warning("DSK integrity: __TEXT segment checksum mismatch — binary has been patched")
            return true
        }
#endif
        return false
    }

    // FNV-1a 64-bit constants
    private static let fnvOffsetBasis: UInt64 = 0xcbf29ce484222325
    private static let fnvPrime: UInt64 = 0x00000100000001B3

    private static func computeTextChecksum() -> UInt64? {
#if !targetEnvironment(simulator)
        // Find the Mach-O header for DSK's image
        let selfPtr = unsafeBitCast(computeTextChecksum as () -> UInt64?, to: UnsafeRawPointer.self)
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
        guard let section = getsectiondata(hdr64, "__TEXT", "__text", &size) else { return nil }
        guard size > 0 else { return nil }

        // FNV-1a over the entire __text section
        let ptr = UnsafeRawPointer(section)
        var hash: UInt64 = fnvOffsetBasis
        for i in 0..<Int(size) {
            hash ^= UInt64(ptr.load(fromByteOffset: i, as: UInt8.self))
            hash = hash &* fnvPrime
        }

        return hash
#else
        return nil
#endif
    }
}
