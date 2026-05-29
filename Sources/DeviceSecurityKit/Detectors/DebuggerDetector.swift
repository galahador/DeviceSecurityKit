//
//  DebuggerDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
import Darwin
import Darwin.C

public final class DebuggerDetector {
    
    private static let logger = SecurityLogger.security(subsystem: "DebuggerDetector")
    private static let debuggerDetectorList = DebuggerDetectorList()
    
    private static let detectionQueue = DispatchQueue(label: "DebuggerDetector.detection", attributes: .concurrent)
    private static var _isDetectionEnabled: Bool = true
    
    private static let denyAttachQueue = DispatchQueue(label: "DebuggerDetector.denyAttach", qos: .background)
    private static var denyAttachTimer: DispatchSourceTimer?
    
    internal static var isDetectionEnabled: Bool {
        get {
            return detectionQueue.sync { _isDetectionEnabled }
        }
        set {
            detectionQueue.sync(flags: .barrier) { _isDetectionEnabled = newValue }
        }
    }
    
    // MARK: - Continuous PT_DENY_ATTACH Hardening
    
    public static func startContinuousDenyAttach(interval: TimeInterval = 1.0) {
#if !DEBUG
        denyAttachQueue.sync {
            guard denyAttachTimer == nil else { return }

            let timer = DispatchSource.makeTimerSource(queue: denyAttachQueue)
            timer.schedule(deadline: .now(), repeating: interval)
            timer.setEventHandler {
                let PT_DENY_ATTACH: Int32 = 31
                _ = ptrace(PT_DENY_ATTACH, 0, nil, 0)
            }
            timer.resume()
            denyAttachTimer = timer
        }
        logger.debug("Continuous PT_DENY_ATTACH hardening started (interval: \(interval)s)")
#endif
    }

    public static func stopContinuousDenyAttach() {
#if !DEBUG
        denyAttachQueue.sync {
            denyAttachTimer?.cancel()
            denyAttachTimer = nil
        }
        logger.debug("Continuous PT_DENY_ATTACH hardening stopped")
#endif
    }
    
    public static func isDebuggerAttached() -> Bool {
        guard isDetectionEnabled else {
            logger.debug("Debugger detection is disabled")
            return false
        }
        
        let detectionResults = [
            ("sysctl", checkDebuggerWithSysctl()),
            ("ptrace", checkDebuggerWithPtrace()),
            ("parentProcess", checkDebuggerWithGetppid()),
            ("environment", checkDebuggerEnvironment()),
            ("timing", checkTimingAnalysis()),
            ("breakpoint", checkBreakpointDetection())
        ]
        
#if DEBUG
        for (method, detected) in detectionResults {
            if detected {
                logger.debug("Debugger detection method '\(method)' triggered")
            }
        }
        return false
#else
        let isAttached = detectionResults.contains { $0.1 }
        if isAttached {
            let triggeredMethods = detectionResults.compactMap { $0.1 ? $0.0 : nil }.joined(separator: ", ")
            logger.warning("Debugger attachment detected via methods: \(triggeredMethods)")
        }
        return isAttached
#endif
    }
    
    public static func getDetectionResults() -> [String: Bool] {
        guard isDetectionEnabled else {
            return [:]
        }
        
        return [
            "sysctl": checkDebuggerWithSysctl(),
            "ptrace": checkDebuggerWithPtrace(),
            "parentProcess": checkDebuggerWithGetppid(),
            "environment": checkDebuggerEnvironment(),
            "timing": checkTimingAnalysis(),
            "breakpoint": checkBreakpointDetection()
        ]
    }
    
    private static func checkDebuggerWithSysctl() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        
        guard result == 0 else {
            logger.error("sysctl failed with result: \(result), errno: \(errno)")
            return false
        }
        
        guard size >= MemoryLayout<kinfo_proc>.stride else {
            logger.error("sysctl returned insufficient data: \(size) bytes")
            return false
        }
        
        let isTraced = (info.kp_proc.p_flag & P_TRACED) != 0
        if isTraced {
            logger.info("P_TRACED flag detected via sysctl")
        }
        
        return isTraced
    }
    
    private static func checkDebuggerWithPtrace() -> Bool {
#if !DEBUG
        let PT_DENY_ATTACH: Int32 = 31
        
        let originalErrno = errno
        errno = 0
        
        let result = ptrace(PT_DENY_ATTACH, 0, nil, 0)
        
        let ptraceErrno = errno
        errno = originalErrno
        
        let detected = result == -1 && ptraceErrno == EBUSY
        if detected {
            logger.info("ptrace detection triggered with errno: \(ptraceErrno)")
        }
        
        return detected
#else
        return false
#endif
    }
    
    private static func checkDebuggerWithGetppid() -> Bool {
        let parentPid = getppid()
        
        guard parentPid > 0 else {
            logger.error("Invalid parent PID: \(parentPid)")
            return false
        }
        
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, parentPid]
        var size = MemoryLayout<kinfo_proc>.stride
        
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        
        guard result == 0 else {
            logger.error("Failed to get parent process info, sysctl returned: \(result)")
            return false
        }
        
        let processName = withUnsafePointer(to: &info.kp_proc.p_comm) { ptr in
            let buffer = UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            return String(cString: buffer)
        }
        
        let detected = debuggerDetectorList.suspiciousNames.contains(processName.lowercased())
        if detected {
            logger.info("Suspicious parent process detected: \(processName)")
        }
        
        return detected
    }
    
    private static func checkDebuggerEnvironment() -> Bool {
        for envVar in debuggerDetectorList.suspiciousEnvVars {
            if let value = getenv(envVar) {
                let envValue = String(cString: value)
                logger.info("Suspicious environment variable detected: \(envVar)=\(envValue)")
                return true
            }
        }
        
        return false
    }
    
    private static func checkTimingAnalysis() -> Bool {
#if !DEBUG
        let iterations = 1000
        let sampleCount = 10

        //calibrates for device speed, thermal state, and CPU load.
        var baselines = [UInt64]()
        baselines.reserveCapacity(sampleCount)
        for _ in 0..<sampleCount {
            let start = mach_absolute_time()
            var sink: UInt64 = 0
            for _ in 0..<iterations {
                sink &+= mach_absolute_time() & 1
            }
            let end = mach_absolute_time()
            baselines.append(end - start)
            withUnsafePointer(to: &sink) { _ in }
        }

        var testTimes = [UInt64]()
        testTimes.reserveCapacity(sampleCount)
        for _ in 0..<sampleCount {
            let start = mach_absolute_time()
            var dummy = 0
            for i in 0..<iterations {
                dummy = dummy &+ i
            }
            let end = mach_absolute_time()
            testTimes.append(end - start)
            withUnsafePointer(to: &dummy) { _ in }
        }

        baselines.sort()
        testTimes.sort()
        let baselineMedian = baselines[sampleCount / 2]
        let testMedian = testTimes[sampleCount / 2]

        guard baselineMedian > 0 else { return false }
        let ratio = testMedian / baselineMedian

        let detected = ratio > 10
        if detected {
            logger.info("Timing analysis: test/baseline ratio \(ratio)x exceeds threshold")
        }
        return detected
#else
        return false
#endif
    }
    
    private static func checkBreakpointDetection() -> Bool {
#if !DEBUG
        let functionPtr = unsafeBitCast(checkBreakpointDetection, to: UnsafeRawPointer.self)
        
#if arch(arm64)
        let instructions = functionPtr.assumingMemoryBound(to: UInt32.self)
        for i in 0..<4 {
            let instr = instructions.advanced(by: i).pointee
            // BRK #imm16 encoding: bits[31:21]=1101_0100_001, bits[4:0]=0_0000
            if (instr & 0xFFE0001F) == 0xD4200000 {
                logger.info("ARM64 breakpoint instruction detected")
                return true
            }
        }
#else
        // x86/x64: INT3 is a single 0xCC byte
        let bytes = functionPtr.assumingMemoryBound(to: UInt8.self)
        for i in 0..<16 {
            if bytes.advanced(by: i).pointee == 0xCC {
                logger.info("x86/x64 breakpoint instruction detected")
                return true
            }
        }
#endif
        
        return false
#else
        return false
#endif
    }
}

private func ptrace(_ request: Int32, _ pid: pid_t, _ addr: UnsafeMutableRawPointer?, _ data: Int32) -> Int32 {
    typealias PtraceType = @convention(c) (Int32, pid_t, UnsafeMutableRawPointer?, Int32) -> Int32
    
    guard let handle = dlopen(nil, RTLD_NOW) else {
        return -1
    }
    defer { dlclose(handle) }
    
    guard let sym = dlsym(handle, "ptrace") else {
        return -1
    }
    
    let ptraceFunc = unsafeBitCast(sym, to: PtraceType.self)
    return ptraceFunc(request, pid, addr, data)
}
