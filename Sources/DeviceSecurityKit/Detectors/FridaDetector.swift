//
//  FridaDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
import Darwin
import MachO

public final class FridaDetector {

    private static let logger = SecurityLogger.security(subsystem: "FridaDetector")
    private static let o = StringObfuscator.shared
    private static let cacheQueue = DispatchQueue(label: "com.devicesecuritykit.frida.cache", attributes: .concurrent)
    private static var _portCheckCache: (date: Date, result: Bool, processCount: Int)?

    public static var portCheckCacheInterval: TimeInterval = 5

    public static let defaultPorts: [UInt16] = [27042, 27043, 27044, 27045, 1337]

    // MARK: - Public
    public static func isFridaDetected(portScanEnabled: Bool = true, ports: [UInt16]? = nil) -> Bool {
        return checkLoadedLibraries()
            || checkFridaSymbols()
            || (portScanEnabled && checkFridaPort(ports: ports ?? defaultPorts))
    }

    public static func collectEvidence(portScanEnabled: Bool = true, ports: [UInt16]? = nil) -> [String] {
        var evidence: [String] = []

        let fridaMarker = o.reveal([0xB5, 0x86, 0x62, 0x8B, 0xC1, 0x43, 0x5E, 0x71, 0x94])
        let count = _dyld_image_count()
        for i in 0..<count {
            guard let rawName = _dyld_get_image_name(i) else { continue }
            let path = String(cString: rawName)
            if path.lowercased().contains(fridaMarker) {
                evidence.append("loadedLibrary(\"\(path)\")")
            }
        }

        let symbols = [
            o.reveal([0x16, 0xD4, 0x14, 0x33, 0x0B, 0xAC, 0xBC, 0x5A, 0x22, 0xBB, 0x4F, 0xBB, 0x98, 0x6C, 0x51, 0xFF, 0x13, 0x0F, 0x28, 0xAA]),
            o.reveal([0xE9, 0xFB, 0xAB, 0xCB, 0x3B, 0x09, 0xBB, 0xDF, 0x13, 0x90, 0x6C, 0xAE, 0x89, 0xC0, 0x8F, 0x9E, 0x73, 0x21, 0x3A, 0x07, 0x42])
        ]
        let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)
        for symbol in symbols {
            if dlsym(rtldDefault, symbol) != nil {
                evidence.append("fridaSymbol(\"\(symbol)\")")
            }
        }

        if portScanEnabled {
            let portsToScan = ports ?? defaultPorts
            let ipAddr = inet_addr(o.reveal([0xA4, 0x4D, 0x21, 0x93, 0xB7, 0xBD, 0xCF, 0xF5, 0xB4, 0x6B, 0x1F, 0x17, 0x77]))
            if ipAddr != in_addr_t(0xFFFF_FFFF) {
                for port in portsToScan {
                    if isPortOpen(port, ipAddr: ipAddr) {
                        evidence.append("openPort(\(port))")
                    }
                }
            }
        }

        return evidence
    }

    // MARK: - Private
    private static func checkLoadedLibraries() -> Bool {
        let fridaMarker = o.reveal([0xB5, 0x86, 0x62, 0x8B, 0xC1, 0x43, 0x5E, 0x71, 0x94])  // "frida"

        let count = _dyld_image_count()
        for i in 0..<count {
            guard let rawName = _dyld_get_image_name(i) else { continue }
            if String(cString: rawName).lowercased().contains(fridaMarker) {
                logger.warning("Frida library detected in loaded images")
                return true
            }
        }
        return false
    }

    private static func checkFridaSymbols() -> Bool {
        let symbols = [
            o.reveal([0x16, 0xD4, 0x14, 0x33, 0x0B, 0xAC, 0xBC, 0x5A, 0x22, 0xBB, 0x4F, 0xBB, 0x98, 0x6C, 0x51, 0xFF, 0x13, 0x0F, 0x28, 0xAA]),          // frida_agent_main
            o.reveal([0xE9, 0xFB, 0xAB, 0xCB, 0x3B, 0x09, 0xBB, 0xDF, 0x13, 0x90, 0x6C, 0xAE, 0x89, 0xC0, 0x8F, 0x9E, 0x73, 0x21, 0x3A, 0x07, 0x42])     // gum_init_embedded
        ]

        let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)

        for symbol in symbols {
            if dlsym(rtldDefault, symbol) != nil {
                logger.warning("Frida symbol present in process memory")
                return true
            }
        }
        return false
    }

    private static func checkFridaPort(ports: [UInt16]) -> Bool {
        let now = Date()
        let currentProcessCount = getProcessCount()

        let cached: Bool? = cacheQueue.sync(flags: .barrier) {
            if let entry = _portCheckCache,
               now.timeIntervalSince(entry.date) < portCheckCacheInterval,
               entry.processCount == currentProcessCount {
                return entry.result
            }
            return nil
        }
        if let cached { return cached }

        let result = performPortCheck(ports: ports)
        cacheQueue.sync(flags: .barrier) {
            _portCheckCache = (now, result, currentProcessCount)
        }
        return result
    }

    private static func getProcessCount() -> Int {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size: Int = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0 else { return -1 }
        return size / MemoryLayout<kinfo_proc>.stride
    }

    private static func performPortCheck(ports: [UInt16]) -> Bool {
        let ipAddr = inet_addr(o.reveal([0xA4, 0x4D, 0x21, 0x93, 0xB7, 0xBD, 0xCF, 0xF5, 0xB4, 0x6B, 0x1F, 0x17, 0x77]))
        guard ipAddr != in_addr_t(0xFFFF_FFFF) else { return false }

        for port in ports {
            if isPortOpen(port, ipAddr: ipAddr) {
                logger.warning("Frida server detected: open port on localhost")
                return true
            }
        }
        return false
    }

    private static func isPortOpen(_ port: UInt16, ipAddr: in_addr_t) -> Bool {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { return false }
        defer { close(sock) }

        let flags = fcntl(sock, F_GETFL, 0)
        guard flags != -1 else { return false }
        _ = fcntl(sock, F_SETFL, flags | O_NONBLOCK)

        var addr = sockaddr_in()
        addr.sin_len         = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family      = sa_family_t(AF_INET)
        addr.sin_port        = port.bigEndian
        addr.sin_addr.s_addr = ipAddr

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        if result == 0 { return true }
        guard result < 0 && errno == EINPROGRESS else { return false }

        var pfd = pollfd(fd: sock, events: Int16(POLLOUT | POLLERR), revents: 0)
        let ready = poll(&pfd, 1, 50)
        guard ready > 0 else { return false }

        var soError: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(sock, SOL_SOCKET, SO_ERROR, &soError, &len) == 0 else { return false }

        return soError == 0
    }
}
