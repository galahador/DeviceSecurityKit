//
//  RepackagingDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 30/05/2026.
//

import Foundation
import CommonCrypto
import MachO

public final class RepackagingDetector {

    private static let logger = SecurityLogger.security(subsystem: "RepackagingDetector")

    private static let CSMAGIC_EMBEDDED_SIGNATURE: UInt32 = 0xFADE0CC0
    private static let CSMAGIC_BLOBWRAPPER: UInt32 = 0xFADE0B01

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
            return nil
        }

        guard let cs = findCodeSignature(in: data) else { return nil }
        guard let cmsBytes = findCMSBlob(in: data, csOffset: cs.offset, csSize: cs.size) else { return nil }
        guard let leafCertBytes = extractLeafCertificateFromCMS(cmsBytes) else { return nil }

        return sha256Hex(leafCertBytes)
    }

    // MARK: - Mach-O Parsing

    private struct CSLocation {
        let offset: Int
        let size: Int
    }

    private static func findCodeSignature(in data: Data) -> CSLocation? {
        return data.withUnsafeBytes { rawBuffer -> CSLocation? in
            guard rawBuffer.count >= MemoryLayout<mach_header_64>.size else { return nil }

            var machOStart = 0

            let fatMagic = rawBuffer.load(as: UInt32.self)
            if fatMagic == FAT_MAGIC || fatMagic == FAT_CIGAM {
                let nArch = UInt32(bigEndian: rawBuffer.load(fromByteOffset: 4, as: UInt32.self))
                for i in 0..<Int(nArch) {
                    let archOff = 8 + i * MemoryLayout<fat_arch>.size
                    guard archOff + MemoryLayout<fat_arch>.size <= rawBuffer.count else { return nil }
                    let cputype = Int32(bigEndian: rawBuffer.load(fromByteOffset: archOff, as: Int32.self))
                    if cputype == CPU_TYPE_ARM64 {
                        machOStart = Int(UInt32(bigEndian: rawBuffer.load(fromByteOffset: archOff + 8, as: UInt32.self)))
                        break
                    }
                }
            }

            guard machOStart + MemoryLayout<mach_header_64>.size <= rawBuffer.count else { return nil }

            let magic = rawBuffer.load(fromByteOffset: machOStart, as: UInt32.self)
            guard magic == MH_MAGIC_64 else { return nil }

            let ncmds = rawBuffer.load(fromByteOffset: machOStart + 16, as: UInt32.self)
            var cmdOffset = machOStart + MemoryLayout<mach_header_64>.size

            for _ in 0..<ncmds {
                guard cmdOffset + 8 <= rawBuffer.count else { return nil }
                let cmd = rawBuffer.load(fromByteOffset: cmdOffset, as: UInt32.self)
                let cmdsize = rawBuffer.load(fromByteOffset: cmdOffset + 4, as: UInt32.self)
                guard cmdsize >= 8 else { return nil }

                if cmd == UInt32(LC_CODE_SIGNATURE) {
                    guard cmdOffset + 16 <= rawBuffer.count else { return nil }
                    let dataoff = rawBuffer.load(fromByteOffset: cmdOffset + 8, as: UInt32.self)
                    let datasize = rawBuffer.load(fromByteOffset: cmdOffset + 12, as: UInt32.self)
                    return CSLocation(offset: Int(dataoff), size: Int(datasize))
                }

                cmdOffset += Int(cmdsize)
            }

            return nil
        }
    }

    // MARK: - Code Signature SuperBlob → CMS Blob

    private static func findCMSBlob(in data: Data, csOffset: Int, csSize: Int) -> Data? {
        return data.withUnsafeBytes { rawBuffer -> Data? in
            let csEnd = csOffset + csSize
            guard csEnd <= rawBuffer.count, csOffset + 12 <= rawBuffer.count else { return nil }

            let magic = UInt32(bigEndian: rawBuffer.load(fromByteOffset: csOffset, as: UInt32.self))
            guard magic == CSMAGIC_EMBEDDED_SIGNATURE else { return nil }

            let count = UInt32(bigEndian: rawBuffer.load(fromByteOffset: csOffset + 8, as: UInt32.self))

            for i in 0..<Int(count) {
                let indexOffset = csOffset + 12 + i * 8
                guard indexOffset + 8 <= rawBuffer.count else { return nil }

                let blobRelOffset = Int(UInt32(bigEndian: rawBuffer.load(fromByteOffset: indexOffset + 4, as: UInt32.self)))
                let blobAbs = csOffset + blobRelOffset
                guard blobAbs + 8 <= rawBuffer.count else { continue }

                let blobMagic = UInt32(bigEndian: rawBuffer.load(fromByteOffset: blobAbs, as: UInt32.self))
                let blobLength = Int(UInt32(bigEndian: rawBuffer.load(fromByteOffset: blobAbs + 4, as: UInt32.self)))

                if blobMagic == CSMAGIC_BLOBWRAPPER {
                    let cmsStart = blobAbs + 8
                    let cmsEnd = blobAbs + blobLength
                    guard cmsEnd <= rawBuffer.count, cmsStart < cmsEnd,
                          let base = rawBuffer.baseAddress else { return nil }
                    return Data(bytes: base.advanced(by: cmsStart), count: cmsEnd - cmsStart)
                }
            }

            return nil
        }
    }

    // MARK: - DER/CMS Certificate Extraction

    /// Extracts the leaf (signing) certificate from a DER-encoded CMS SignedData envelope.
    ///
    /// CMS structure:
    /// ```
    /// SEQUENCE (ContentInfo)
    ///   OID 1.2.840.113549.1.7.2 (signedData)
    ///   [0] EXPLICIT
    ///     SEQUENCE (SignedData)
    ///       INTEGER (version)
    ///       SET (digestAlgorithms)
    ///       SEQUENCE (encapContentInfo)
    ///       [0] IMPLICIT (certificates)  ← target
    ///         SEQUENCE (leaf certificate) ← extracted
    ///         SEQUENCE (intermediate)
    ///         ...
    /// ```
    private static func extractLeafCertificateFromCMS(_ cms: Data) -> Data? {
        var pos = 0

        // Outer SEQUENCE (ContentInfo)
        guard let _ = readDER(cms, at: &pos, expectTag: 0x30) else { return nil }

        // OID (primitive auto-skipped)
        guard let _ = readDER(cms, at: &pos, expectTag: 0x06) else { return nil }

        // [0] EXPLICIT content
        guard let _ = readDER(cms, at: &pos, expectTag: 0xA0) else { return nil }

        // SEQUENCE (SignedData)
        guard let _ = readDER(cms, at: &pos, expectTag: 0x30) else { return nil }

        // INTEGER (version) primitive, auto-skipped
        guard let _ = readDER(cms, at: &pos, expectTag: 0x02) else { return nil }

        // SET (digestAlgorithms) skip over
        guard let digestAlgs = readDER(cms, at: &pos, expectTag: 0x31) else { return nil }
        pos = digestAlgs.elementEnd

        // SEQUENCE (encapContentInfo) skip over
        guard let contentInfo = readDER(cms, at: &pos, expectTag: 0x30) else { return nil }
        pos = contentInfo.elementEnd

        // [0] IMPLICIT (certificates)
        guard let _ = readDER(cms, at: &pos, expectTag: 0xA0) else { return nil }

        // First SEQUENCE inside = leaf certificate
        let certStart = pos
        guard let leafCert = readDER(cms, at: &pos, expectTag: 0x30) else { return nil }

        return cms.subdata(in: certStart..<leafCert.elementEnd)
    }

    // MARK: - Minimal DER Reader

    private struct DERElement {
        let tag: UInt8
        let contentStart: Int
        let contentLength: Int
        var contentEnd: Int { contentStart + contentLength }
        var elementEnd: Int { contentStart + contentLength }
    }

    private static func readDER(_ data: Data, at pos: inout Int, expectTag: UInt8? = nil) -> DERElement? {
        guard pos < data.count else { return nil }
        let tag = data[pos]
        if let expected = expectTag, tag != expected { return nil }
        pos += 1

        guard pos < data.count else { return nil }
        let firstLenByte = data[pos]
        pos += 1

        var length: Int
        if firstLenByte & 0x80 == 0 {
            length = Int(firstLenByte)
        } else {
            let numBytes = Int(firstLenByte & 0x7F)
            guard numBytes > 0, numBytes <= 4, pos + numBytes <= data.count else { return nil }
            length = 0
            for _ in 0..<numBytes {
                length = (length << 8) | Int(data[pos])
                pos += 1
            }
        }

        let contentStart = pos
        guard contentStart + length <= data.count else { return nil }

        let isConstructed = (tag & 0x20) != 0
        if !isConstructed {
            pos = contentStart + length
        }

        return DERElement(tag: tag, contentStart: contentStart, contentLength: length)
    }

    // MARK: - Hashing

    private static func sha256Hex(_ data: Data) -> String {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { buffer in
            _ = CC_SHA256(buffer.baseAddress, CC_LONG(buffer.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}
