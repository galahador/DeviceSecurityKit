//
//  DebuggerDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
import Darwin
import Darwin.C
import MachO

public final class DebuggerDetector {

    private struct Constants {
        static let loggerSubsystem = "DebuggerDetector"
        static let denyAttachQueueLabel = "DebuggerDetector.denyAttach"

        static let methodSysctl = "sysctl"
        static let methodPtrace = "ptrace"
        static let methodParentProcess = "parentProcess"
        static let methodEnvironment = "environment"
        static let methodTiming = "timing"
        static let methodBreakpoint = "breakpoint"
        static let methodTextIntegrity = "textIntegrity"
        static let methodExceptionPorts = "exceptionPorts"
        static let methodSeparator = ", "
        static let listSeparator = ","

        static let textSegment = "__TEXT"
        static let textSection = "__text"

        static let denyAttachStopped = "Continuous PT_DENY_ATTACH hardening stopped"
        static let ptracedFlag = "P_TRACED flag detected via sysctl"
        static let arm64Breakpoint = "ARM64 breakpoint instruction detected"
        static let x86Breakpoint = "x86/x64 breakpoint instruction detected"
        static let textIntegrityFailed = "Text segment integrity check failed — possible breakpoint insertion"

        static func denyAttachStarted(_ interval: some CustomStringConvertible) -> String {
            "Continuous PT_DENY_ATTACH hardening started (interval: \(interval)s)"
        }
        static func methodTriggered(_ method: String) -> String {
            "Debugger detection method '\(method)' triggered"
        }
        static func attachedVia(_ methods: String) -> String {
            "Debugger attachment detected via methods: \(methods)"
        }
        static func sysctlFailed(_ result: some CustomStringConvertible, _ errno: some CustomStringConvertible) -> String {
            "sysctl failed with result: \(result), errno: \(errno)"
        }
        static func sysctlInsufficient(_ size: some CustomStringConvertible) -> String {
            "sysctl returned insufficient data: \(size) bytes"
        }
        static func ptraceTriggered(_ errno: some CustomStringConvertible) -> String {
            "ptrace detection triggered with errno: \(errno)"
        }
        static func invalidParentPid(_ pid: some CustomStringConvertible) -> String {
            "Invalid parent PID: \(pid)"
        }
        static func parentInfoFailed(_ result: some CustomStringConvertible) -> String {
            "Failed to get parent process info, sysctl returned: \(result)"
        }
        static func suspiciousParent(_ name: String) -> String {
            "Suspicious parent process detected: \(name)"
        }
        static func suspiciousEnvVar(_ name: String, _ value: String) -> String {
            "Suspicious environment variable detected: \(name)=\(value)"
        }
        static func timingExceeded(_ ratio: some CustomStringConvertible) -> String {
            "Timing analysis: test/baseline ratio \(ratio)x exceeds threshold"
        }
        static func exceptionPortsFailed(_ result: some CustomStringConvertible) -> String {
            "task_get_exception_ports failed with result: \(result)"
        }
        static func exceptionPortSignature(_ mask: some CustomStringConvertible, _ behavior: some CustomStringConvertible, _ flavor: some CustomStringConvertible) -> String {
            "\(mask):\(behavior):\(flavor)"
        }
        static func newExceptionPort(_ signatures: String) -> String {
            "New exception port handler detected: \(signatures)"
        }
    }
    
    // MARK: - Public
    public static var timingThreshold: UInt64 = 10

    // MARK: - Private Properties
    private static let logger = SecurityLogger.security(subsystem: Constants.loggerSubsystem)
    private static let debuggerDetectorList = DebuggerDetectorList()
    private static let denyAttachQueue = DispatchQueue(label: Constants.denyAttachQueueLabel, qos: .background)
    private static var denyAttachTimer: DispatchSourceTimer?
    private static let exceptionPortLock = NSLock()
    private static var exceptionPortBaseline: Set<String>?
    
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
        logger.debug(Constants.denyAttachStarted(interval))
#endif
    }

    public static func stopContinuousDenyAttach() {
#if !DEBUG
        denyAttachQueue.sync {
            denyAttachTimer?.cancel()
            denyAttachTimer = nil
        }
        logger.debug(Constants.denyAttachStopped)
#endif
    }
    
    public static func isDebuggerAttached() -> Bool {
        let detectionResults = [
            (Constants.methodSysctl, checkDebuggerWithSysctl()),
            (Constants.methodPtrace, checkDebuggerWithPtrace()),
            (Constants.methodParentProcess, checkDebuggerWithGetppid()),
            (Constants.methodEnvironment, checkDebuggerEnvironment()),
            (Constants.methodTiming, checkTimingAnalysis()),
            (Constants.methodBreakpoint, checkBreakpointDetection()),
            (Constants.methodTextIntegrity, checkTextSegmentIntegrity()),
            (Constants.methodExceptionPorts, checkExceptionPorts())
        ]

#if DEBUG
        for (method, detected) in detectionResults {
            if detected {
                logger.debug(Constants.methodTriggered(method))
            }
        }
        return false
#else
        let isAttached = detectionResults.contains { $0.1 }
        if isAttached {
            let triggeredMethods = detectionResults.compactMap { $0.1 ? $0.0 : nil }.joined(separator: Constants.methodSeparator)
            logger.warning(Constants.attachedVia(triggeredMethods))
        }
        return isAttached
#endif
    }
    
    public static func getDetectionResults() -> [String: Bool] {
        return [
            Constants.methodSysctl: checkDebuggerWithSysctl(),
            Constants.methodPtrace: checkDebuggerWithPtrace(),
            Constants.methodParentProcess: checkDebuggerWithGetppid(),
            Constants.methodEnvironment: checkDebuggerEnvironment(),
            Constants.methodTiming: checkTimingAnalysis(),
            Constants.methodBreakpoint: checkBreakpointDetection(),
            Constants.methodTextIntegrity: checkTextSegmentIntegrity(),
            Constants.methodExceptionPorts: checkExceptionPorts()
        ]
    }
    
    private static func checkDebuggerWithSysctl() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        
        guard result == 0 else {
            logger.error(Constants.sysctlFailed(result, errno))
            return false
        }
        
        guard size >= MemoryLayout<kinfo_proc>.stride else {
            logger.error(Constants.sysctlInsufficient(size))
            return false
        }
        
        let isTraced = (info.kp_proc.p_flag & P_TRACED) != 0
        if isTraced {
            logger.info(Constants.ptracedFlag)
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
            logger.info(Constants.ptraceTriggered(ptraceErrno))
        }
        
        return detected
#else
        return false
#endif
    }
    
    private static func checkDebuggerWithGetppid() -> Bool {
        let parentPid = getppid()
        
        guard parentPid > 0 else {
            logger.error(Constants.invalidParentPid(parentPid))
            return false
        }
        
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, parentPid]
        var size = MemoryLayout<kinfo_proc>.stride
        
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        
        guard result == 0 else {
            logger.error(Constants.parentInfoFailed(result))
            return false
        }
        
        let processName = withUnsafePointer(to: &info.kp_proc.p_comm) { ptr in
            let buffer = UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            return String(cString: buffer)
        }
        
        let detected = debuggerDetectorList.suspiciousNames.contains(processName.lowercased())
        if detected {
            logger.info(Constants.suspiciousParent(SecurityLogger.redact(processName)))
        }
        
        return detected
    }
    
    private static func checkDebuggerEnvironment() -> Bool {
        for envVar in debuggerDetectorList.suspiciousEnvVars {
            if let value = getenv(envVar) {
                let envValue = String(cString: value)
                logger.info(Constants.suspiciousEnvVar(SecurityLogger.redact(envVar), SecurityLogger.redact(envValue)))
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

        let detected = ratio > timingThreshold
        if detected {
            logger.info(Constants.timingExceeded(ratio))
        }
        return detected
#else
        return false
#endif
    }
    
    private static func checkBreakpointDetection() -> Bool {
#if !DEBUG
        let targets: [UnsafeRawPointer] = [
            FunctionAddress.of(checkBreakpointDetection as () -> Bool),
            FunctionAddress.of(checkDebuggerWithSysctl as () -> Bool),
            FunctionAddress.of(checkDebuggerWithPtrace as () -> Bool),
            FunctionAddress.of(checkDebuggerWithGetppid as () -> Bool),
            FunctionAddress.of(checkDebuggerEnvironment as () -> Bool)
        ]

        let scanDepth = 64

        for funcPtr in targets {
#if arch(arm64)
            let instructions = funcPtr.assumingMemoryBound(to: UInt32.self)
            for i in 0..<scanDepth {
                let instr = instructions.advanced(by: i).pointee
                
                if instr == 0xD4200000 {
                    logger.info(Constants.arm64Breakpoint)
                    return true
                }
                if instr == 0xD65F03C0 || instr == 0xD65F0FFF || instr == 0xD65F0BFF { break }
            }
#else
            let bytes = funcPtr.assumingMemoryBound(to: UInt8.self)
            for i in 0..<scanDepth {
                if bytes.advanced(by: i).pointee == 0xCC {
                    logger.info(Constants.x86Breakpoint)
                    return true
                }
                if bytes.advanced(by: i).pointee == 0xC3 { break }
            }
#endif
        }

        return false
#else
        return false
#endif
    }

    // MARK: - Text Segment Integrity Check

    private static func checkTextSegmentIntegrity() -> Bool {
#if !DEBUG && arch(arm64)
        guard let header = _dyld_get_image_header(0) else { return false }
        var size: UInt = 0
        guard let section = header.withMemoryRebound(to: mach_header_64.self, capacity: 1, {
            getsectiondata($0, Constants.textSegment, Constants.textSection, &size)
        }) else { return false }
        guard size > 0 else { return false }

        let checkSize = min(Int(size), 4096)
        let ptr = UnsafeRawPointer(section)

        var sum1: UInt64 = 0
        for i in 0..<checkSize {
            sum1 = sum1 &+ UInt64(ptr.load(fromByteOffset: i, as: UInt8.self))
            sum1 = (sum1 << 1) | (sum1 >> 63) // rotate left
        }

        var dummy = 0
        for i in 0..<100 { dummy = dummy &+ i }
        withUnsafePointer(to: &dummy) { _ in }

        var sum2: UInt64 = 0
        for i in 0..<checkSize {
            sum2 = sum2 &+ UInt64(ptr.load(fromByteOffset: i, as: UInt8.self))
            sum2 = (sum2 << 1) | (sum2 >> 63)
        }

        if sum1 != sum2 {
            logger.info(Constants.textIntegrityFailed)
            return true
        }

        return false
#else
        return false
#endif
    }

    // MARK: - Exception Port Hijack Check

    private static func checkExceptionPorts() -> Bool {
#if !DEBUG
        let exceptionMask = exception_mask_t(
            EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_ARITHMETIC |
            EXC_MASK_SOFTWARE | EXC_MASK_BREAKPOINT
        )

        let portCount = Int(EXC_TYPES_COUNT)
        var masks = [exception_mask_t](repeating: 0, count: portCount)
        var ports = [mach_port_t](repeating: 0, count: portCount)
        var behaviors = [exception_behavior_t](repeating: 0, count: portCount)
        var flavors = [thread_state_flavor_t](repeating: 0, count: portCount)
        var maskCount = mach_msg_type_number_t(portCount)

        let result = task_get_exception_ports(
            mach_task_self_,
            exceptionMask,
            &masks,
            &maskCount,
            &ports,
            &behaviors,
            &flavors
        )

        guard result == KERN_SUCCESS else {
            logger.error(Constants.exceptionPortsFailed(result))
            return false
        }

        var signatures = Set<String>()
        for i in 0..<Int(maskCount) {
            if ports[i] != mach_port_t(MACH_PORT_NULL) {
                signatures.insert(Constants.exceptionPortSignature(masks[i], behaviors[i], flavors[i]))
                mach_port_deallocate(mach_task_self_, ports[i])
            }
        }

        exceptionPortLock.lock()
        defer { exceptionPortLock.unlock() }
        guard let baseline = exceptionPortBaseline else {
            exceptionPortBaseline = signatures
            return false
        }

        let added = signatures.subtracting(baseline)
        if !added.isEmpty {
            logger.info(Constants.newExceptionPort(added.sorted().joined(separator: Constants.listSeparator)))
        }
        return !added.isEmpty
#else
        return false
#endif
    }
}

private struct PtraceConstants {
    static let symbol = "ptrace"
}

private func ptrace(_ request: Int32, _ pid: pid_t, _ addr: UnsafeMutableRawPointer?, _ data: Int32) -> Int32 {
    typealias PtraceType = @convention(c) (Int32, pid_t, UnsafeMutableRawPointer?, Int32) -> Int32
    
    guard let handle = dlopen(nil, RTLD_NOW) else {
        return -1
    }
    defer { dlclose(handle) }
    
    guard let sym = dlsym(handle, PtraceConstants.symbol) else {
        return -1
    }
    
    let ptraceFunc = unsafeBitCast(sym, to: PtraceType.self)
    return ptraceFunc(request, pid, addr, data)
}
