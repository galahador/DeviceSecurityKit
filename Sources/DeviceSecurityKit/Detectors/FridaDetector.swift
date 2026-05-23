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
    private static var _portCheckCache: (date: Date, result: Bool)?
    private static let portCheckCacheInterval: TimeInterval = 60

    // MARK: - Public
    public static func isFridaDetected() -> Bool {
        return checkLoadedLibraries()
            || checkFridaSymbols()
            || checkFridaPort()
    }

    // MARK: - Private
    private static func checkLoadedLibraries() -> Bool {
        let fridaMarker = o.reveal([0xCC, 0xD8, 0xC3, 0xCE, 0xCB])  // "frida"

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
            o.reveal([0xCC, 0xD8, 0xC3, 0xCE, 0xCB, 0xF5, 0xCB, 0xCD, 0xCF, 0xC4, 0xDE, 0xF5, 0xC7, 0xCB, 0xC3, 0xC4]),          // frida_agent_main
            o.reveal([0xCD, 0xDF, 0xC7, 0xF5, 0xC3, 0xC4, 0xC3, 0xDE, 0xF5, 0xCF, 0xC7, 0xC8, 0xCF, 0xCE, 0xCE, 0xCF, 0xCE])     // gum_init_embedded
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

    private static func checkFridaPort() -> Bool {
        let now = Date()
        if let cached = cacheQueue.sync(execute: { _portCheckCache }),
           now.timeIntervalSince(cached.date) < portCheckCacheInterval {
            return cached.result
        }
        let result = performPortCheck()
        cacheQueue.sync(flags: .barrier) { _portCheckCache = (now, result) }
        return result
    }

    private static func performPortCheck() -> Bool {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { return false }
        defer { close(sock) }

        let flags = fcntl(sock, F_GETFL, 0)
        guard flags != -1 else { return false }
        _ = fcntl(sock, F_SETFL, flags | O_NONBLOCK)

        let ipAddr = inet_addr(o.reveal([0x9B, 0x98, 0x9D, 0x84, 0x9A, 0x84, 0x9A, 0x84, 0x9B]))
        guard ipAddr != in_addr_t(0xFFFF_FFFF) else { return false }  // INADDR_NONE

        var addr = sockaddr_in()
        addr.sin_len         = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family      = sa_family_t(AF_INET)
        addr.sin_port        = UInt16(27042).bigEndian
        addr.sin_addr.s_addr = ipAddr

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        if result == 0 {
            logger.warning("Frida server detected: port 27042 is open on localhost")
            return true
        }

        guard result < 0 && errno == EINPROGRESS else { return false }

        var pfd = pollfd(fd: sock, events: Int16(POLLOUT | POLLERR), revents: 0)
        let ready = poll(&pfd, 1, 50)
        guard ready > 0 else { return false }

        var soError: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(sock, SOL_SOCKET, SO_ERROR, &soError, &len) == 0 else { return false }

        if soError == 0 {
            logger.warning("Frida server detected: port 27042 is open on localhost")
            return true
        }

        return false
    }
}
