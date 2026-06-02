//
//  SecurityMonitor.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

public final class SecurityMonitor: SecurityMonitorType, @unchecked Sendable {

    // MARK: - Private Properties
    private var monitoringTimer: DispatchSourceTimer?
    private let timerQueue = DispatchQueue(label: "com.devicesecuritykit.monitor", qos: .userInitiated)

    private let stateQueue = DispatchQueue(
        label: "com.devicesecuritykit.monitor.state",
        qos: .userInitiated,
        attributes: .concurrent
    )

    private var configuration: DeviceSecurityConfiguration
    private var hasPerformedInitialCheck = false
    private var isMonitoring = false
    private var _status: SecurityStatus = .secure
    private var _previousThreats: Set<SecurityThreat> = []
    private var _lastThreatCallbackTime: [SecurityThreat: Date] = [:]
    private var _threatCallbackThrottleInterval: TimeInterval = 300

    // MARK: - Handlers (protected by stateQueue)
    private var _onStatusChange: ((SecurityStatus) -> Void)?
    private var _onThreatDetected: ((SecurityThreat) -> Void)?
    private var _onThreatEvent: ((ThreatEvent) -> Void)?
    private var _screenRecordingProvider: ScreenRecordingProvider? = DefaultScreenRecordingProvider()
    private var _countermeasures: [Countermeasure] = []

    // MARK: - Threat History (ring buffer, protected by stateQueue)
    private var _threatHistory: [ThreatEvent] = []
    private var _threatHistoryMaxSize: Int = 100

    // MARK: - Public Properties
    public var status: SecurityStatus {
        stateQueue.sync { _status }
    }

    // MARK: - Adaptive Interval
    private var _currentInterval: TimeInterval = 60.0
    private var _minInterval: TimeInterval = 5.0
    private var _maxInterval: TimeInterval = 300.0
    private var _baseInterval: TimeInterval = 60.0
    private var _consecutiveCleanCycles: Int = 0

    public var monitoringInterval: TimeInterval {
        get { stateQueue.sync { _baseInterval } }
        set {
            stateQueue.sync(flags: .barrier) {
                _baseInterval = newValue
                _currentInterval = newValue
                _consecutiveCleanCycles = 0
            }
        }
    }

    public var minMonitoringInterval: TimeInterval {
        get { stateQueue.sync { _minInterval } }
        set { stateQueue.sync(flags: .barrier) { _minInterval = max(newValue, 1.0) } }
    }

    public var maxMonitoringInterval: TimeInterval {
        get { stateQueue.sync { _maxInterval } }
        set { stateQueue.sync(flags: .barrier) { _maxInterval = newValue } }
    }

    public var currentMonitoringInterval: TimeInterval {
        stateQueue.sync { _currentInterval }
    }

    public var threatCallbackThrottleInterval: TimeInterval {
        get { stateQueue.sync { _threatCallbackThrottleInterval } }
        set { stateQueue.sync(flags: .barrier) { _threatCallbackThrottleInterval = newValue } }
    }

    public var screenRecordingProvider: ScreenRecordingProvider? {
        get { stateQueue.sync { _screenRecordingProvider } }
        set { stateQueue.sync(flags: .barrier) { _screenRecordingProvider = newValue } }
    }

    public var threatHistory: [ThreatEvent] {
        stateQueue.sync { _threatHistory }
    }

    public var threatHistoryMaxSize: Int {
        get { stateQueue.sync { _threatHistoryMaxSize } }
        set {
            stateQueue.sync(flags: .barrier) {
                _threatHistoryMaxSize = max(newValue, 0)
                if _threatHistory.count > _threatHistoryMaxSize {
                    _threatHistory.removeFirst(_threatHistory.count - _threatHistoryMaxSize)
                }
            }
        }
    }

    public func clearThreatHistory() {
        stateQueue.sync(flags: .barrier) { _threatHistory.removeAll() }
    }

    // MARK: - Initialization

    public init(configuration: DeviceSecurityConfiguration = .default) {
        self.configuration = configuration
        DSKIntegrityChecker.captureBaseline()
    }

    deinit {
        stopMonitoring()
    }

    // MARK: - Configuration

    public func configure(_ configuration: DeviceSecurityConfiguration) {
        stateQueue.sync(flags: .barrier) { self.configuration = configuration }

        if stateQueue.sync(execute: { isMonitoring }) {
            runChecks()
        }
    }

    public func currentConfiguration() -> DeviceSecurityConfiguration {
        stateQueue.sync { configuration }
    }

    // MARK: - Handlers
    @discardableResult
    public func onStatusChange(_ handler: @escaping (SecurityStatus) -> Void) -> Self {
        stateQueue.sync(flags: .barrier) { _onStatusChange = handler }
        return self
    }

    @discardableResult
    public func onThreatDetected(_ handler: @escaping (SecurityThreat) -> Void) -> Self {
        stateQueue.sync(flags: .barrier) { _onThreatDetected = handler }
        return self
    }

    @discardableResult
    public func onThreatEvent(_ handler: @escaping (ThreatEvent) -> Void) -> Self {
        stateQueue.sync(flags: .barrier) { _onThreatEvent = handler }
        return self
    }

    // MARK: - Countermeasures

    @discardableResult
    public func addCountermeasure(_ countermeasure: Countermeasure) -> Self {
        if case .threat(let t) = countermeasure.trigger, t == .noThreat {
            return self
        }
        stateQueue.sync(flags: .barrier) { _countermeasures.append(countermeasure) }
        return self
    }

    @discardableResult
    public func removeCountermeasure(_ countermeasure: Countermeasure) -> Self {
        stateQueue.sync(flags: .barrier) { _countermeasures.removeAll { $0 == countermeasure } }
        return self
    }

    public func removeAllCountermeasures() {
        stateQueue.sync(flags: .barrier) { _countermeasures.removeAll() }
    }

    // MARK: - Check Methods

    public func performCheck() -> SecurityResult {
        let result = gatherThreats()
        let pending = stateQueue.sync(flags: .barrier) { applyResult(result) }
        firePending(pending, evidence: result.evidence)
        return result
    }

    public func isSecure() -> Bool {
        return performCheck().isSecure
    }

    // MARK: - Async

    @available(iOS 15.0, *)
    public func performCheckAsync() async -> SecurityResult {
        await withCheckedContinuation { continuation in
            timerQueue.async { [weak self] in
                guard let self else {
                    continuation.resume(returning: SecurityResult(threats: [], evidence: [:]))
                    return
                }
                let result = self.performCheck()
                continuation.resume(returning: result)
            }
        }
    }

    @available(iOS 15.0, *)
    public func isSecureAsync() async -> Bool {
        await performCheckAsync().isSecure
    }

    // MARK: - Monitoring

    public func startMonitoring() {
        let alreadyRunning = stateQueue.sync(flags: .barrier) { () -> Bool in
            if isMonitoring { return true }
            isMonitoring = true
            return false
        }
        guard !alreadyRunning else { return }

#if !DEBUG
        if stateQueue.sync(execute: { configuration.debuggerCheckEnabled }) {
            DebuggerDetector.startContinuousDenyAttach()
        }
#endif

        if stateQueue.sync(execute: { configuration.screenshotDetectionEnabled }) {
            ScreenshotDetector.startObserving()
        }

        // Run an immediate first check so the caller isn't blind for the first interval
        runChecks()
        scheduleNextCheck()
    }

    public func stopMonitoring() {
        timerQueue.sync {
            monitoringTimer?.cancel()
            monitoringTimer = nil
        }
        stateQueue.sync(flags: .barrier) {
            isMonitoring = false
            _currentInterval = _baseInterval
            _consecutiveCleanCycles = 0
        }
#if !DEBUG
        DebuggerDetector.stopContinuousDenyAttach()
#endif
        ScreenshotDetector.stopObserving()
    }

    // MARK: - Private

    private func runChecks() {
        let result = gatherThreats()
        // Bug 6 fix: applyResult writes multiple state fields — needs .barrier.
        let pending = stateQueue.sync(flags: .barrier) { applyResult(result) }
        firePending(pending, evidence: result.evidence)

        // Adapt interval based on threat presence
        let hasThreats = !result.threats.isEmpty
        let (interval, cycles) = stateQueue.sync(flags: .barrier) { () -> (TimeInterval, Int) in
            if hasThreats {
                _consecutiveCleanCycles = 0
                _currentInterval = _minInterval
            } else {
                _consecutiveCleanCycles += 1
                let backoff = _baseInterval * pow(2.0, Double(min(_consecutiveCleanCycles, 10)))
                _currentInterval = min(max(backoff, _minInterval), _maxInterval)
            }
            return (_currentInterval, _consecutiveCleanCycles)
        }
        Self.logger.debug("Adaptive interval: \(interval)s (cleanCycles: \(cycles), threats: \(hasThreats))")
    }

    /// Schedules the next one-shot check on `timerQueue`.
    private func scheduleNextCheck() {
        let interval = stateQueue.sync { _currentInterval }

        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.schedule(deadline: .now() + interval)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.runChecks()
            if self.stateQueue.sync(execute: { self.isMonitoring }) {
                self.scheduleNextCheck()
            }
        }
        timerQueue.async { [weak self] in
            self?.monitoringTimer?.cancel()
            self?.monitoringTimer = timer
            timer.resume()
        }
    }

    private static let logger = SecurityLogger.security(subsystem: "SecurityMonitor")

    private static let detectorQueue = DispatchQueue(
        label: "com.devicesecuritykit.monitor.detectors",
        qos: .userInitiated,
        attributes: .concurrent
    )

    private func runDetector<T>(timeout: TimeInterval, _ body: @escaping () -> T) -> T? {
        var result: T?
        let group = DispatchGroup()
        group.enter()
        Self.detectorQueue.async {
            result = body()
            group.leave()
        }
        let status = group.wait(timeout: .now() + timeout)
        if status == .timedOut {
            Self.logger.warning("Detector timed out after \(timeout)s")
            return nil
        }
        return result
    }

    private func gatherThreats() -> SecurityResult {
        let (cfg, provider) = stateQueue.sync { (configuration, _screenRecordingProvider) }
        let timeout = cfg.detectorTimeout
        var threats: [SecurityThreat] = []
        var evidence: [SecurityThreat: [String]] = [:]

        if cfg.jailbreakCheckEnabled {
            if runDetector(timeout: timeout, { JailbreakDetector.isJailbroken() }) == true {
                threats.append(.jailbreak)
                evidence[.jailbreak] = JailbreakDetector.getDetectionDetails()
            }
        }
        if cfg.debuggerCheckEnabled {
            if runDetector(timeout: timeout, { DebuggerDetector.isDebuggerAttached() }) == true {
                threats.append(.debugger)
                let results = DebuggerDetector.getDetectionResults()
                evidence[.debugger] = results.filter { $0.value }.map { $0.key }
            }
        }
        #if !DEBUG
        if cfg.emulatorCheckEnabled {
            if let result = runDetector(timeout: timeout, { EmulatorDetector.detectEmulator() }),
               result.isEmulator {
                threats.append(.emulator)
                evidence[.emulator] = result.detectionMethods
            }
        }
        #endif
        if cfg.reverseEngineeringCheckEnabled {
            if runDetector(timeout: timeout, { ReverseEngineeringDetector.isReverseEngineered() }) == true {
                threats.append(.reverseEngineering)
                evidence[.reverseEngineering] = ["reverseEngineeringToolDetected"]
            }
        }
        if cfg.appIntegrityCheckEnabled {
            if runDetector(timeout: timeout, { AppIntegrityDetector.isIntegrityCompromised(expectedTeamID: cfg.expectedTeamID) }) == true {
                threats.append(.appIntegrity)
                evidence[.appIntegrity] = ["integrityCheckFailed"]
            }
        }
        if cfg.screenRecordingCheckEnabled, let provider {
            if runDetector(timeout: timeout, { provider.isScreenBeingRecorded() }) == true {
                threats.append(.screenRecording)
                evidence[.screenRecording] = ["screenBeingRecorded"]
            }
        }
        if cfg.hookDetectionEnabled {
            if runDetector(timeout: timeout, { HookDetector.isFunctionHooked() }) == true {
                threats.append(.hooked)
                evidence[.hooked] = HookDetector.collectEvidence()
            }
        }
        if cfg.pinningBypassDetectionEnabled {
            if runDetector(timeout: timeout, { CertificatePinningDetector.isPinningBypassed() }) == true {
                threats.append(.pinningBypassed)
                evidence[.pinningBypassed] = ["pinningBypassDetected"]
            }
        }
        if cfg.vpnProxyDetectionEnabled {
            if runDetector(timeout: timeout, { VPNProxyDetector.isVPNActive(allowedVPNBundleIDs: cfg.allowedVPNBundleIDs) }) == true {
                threats.append(.vpnDetected)
                evidence[.vpnDetected] = ["vpnConnectionActive"]
            }
            if runDetector(timeout: timeout, { VPNProxyDetector.isProxyActive() }) == true {
                threats.append(.proxyDetected)
                evidence[.proxyDetected] = ["proxyConfigured"]
            }
        }
        if cfg.swizzlingDetectionEnabled {
            if runDetector(timeout: timeout, { SwizzlingDetector.isSwizzled() }) == true {
                threats.append(.methodSwizzling)
                evidence[.methodSwizzling] = ["methodSwizzlingDetected"]
            }
        }
        if cfg.fridaDetectionEnabled {
            if runDetector(timeout: timeout, { FridaDetector.isFridaDetected(portScanEnabled: cfg.fridaPortScanEnabled, ports: cfg.fridaPorts) }) == true {
                threats.append(.fridaDetected)
                evidence[.fridaDetected] = FridaDetector.collectEvidence(portScanEnabled: cfg.fridaPortScanEnabled, ports: cfg.fridaPorts)
            }
        }
        if cfg.attestationCheckEnabled {
            if runDetector(timeout: timeout, { AttestationDetector.isAttestationFailed() }) == true {
                threats.append(.attestationFailed)
                evidence[.attestationFailed] = ["attestationFailed"]
            }
        }
        // DSK integrity always runs — not gated by config
        if runDetector(timeout: timeout, { DSKIntegrityChecker.isDSKCompromised() }) == true {
            threats.append(.dskTampered)
            evidence[.dskTampered] = ["dskIntegrityCheckFailed"]
        }
        if cfg.antiRepackagingEnabled {
            if runDetector(timeout: timeout, { RepackagingDetector.isRepackaged(expectedCertificateHash: cfg.expectedCertificateHash) }) == true {
                threats.append(.repackaged)
                evidence[.repackaged] = ["signingCertificateMismatch"]
            }
        }
        if cfg.screenshotDetectionEnabled {
            if runDetector(timeout: timeout, { ScreenshotDetector.wasScreenshotTaken() }) == true {
                threats.append(.screenshotTaken)
                evidence[.screenshotTaken] = ["screenshotDetectedInWindow"]
            }
        }
        if cfg.dylibInjectionDetectionEnabled {
            if runDetector(timeout: timeout, { DylibInjectionDetector.isDylibInjected() }) == true {
                threats.append(.dylibInjection)
                evidence[.dylibInjection] = DylibInjectionDetector.collectEvidence()
            }
        }

        return SecurityResult(threats: threats, evidence: evidence)
    }

    private func applyResult(_ result: SecurityResult) -> (
        statusChange: SecurityStatus?,
        newThreats: [SecurityThreat],
        currentThreats: [SecurityThreat],
        detectedAt: Date
    ) {
        let newStatus = mapToStatus(result)
        var statusChange: SecurityStatus?
        if newStatus != _status {
            _status = newStatus
            statusChange = newStatus
        }

        let currentThreats = Set(result.threats)
        let candidateThreats = currentThreats.subtracting(_previousThreats)
        _previousThreats = currentThreats
        hasPerformedInitialCheck = true

        let now = Date()
        let newThreats = Array(candidateThreats.filter { threat in
            guard let last = _lastThreatCallbackTime[threat] else { return true }
            return now.timeIntervalSince(last) >= _threatCallbackThrottleInterval
        })
        for threat in newThreats {
            _lastThreatCallbackTime[threat] = now
        }

        return (statusChange, newThreats, Array(currentThreats), now)
    }

    private func firePending(
        _ pending: (
            statusChange: SecurityStatus?,
            newThreats: [SecurityThreat],
            currentThreats: [SecurityThreat],
            detectedAt: Date
        ),
        evidence: [SecurityThreat: [String]]
    ) {
        guard pending.statusChange != nil || !pending.newThreats.isEmpty || !pending.currentThreats.isEmpty else { return }

        let (statusHandler, threatHandler, threatEventHandler, countermeasures) = stateQueue.sync {
            (_onStatusChange, _onThreatDetected, _onThreatEvent, _countermeasures)
        }

        // Build ThreatEvents for new threats
        let events = pending.newThreats.map { threat in
            ThreatEvent(
                threat: threat,
                severity: threat.severity,
                detectedAt: pending.detectedAt,
                evidence: evidence[threat] ?? []
            )
        }

        // Record into ring buffer
        if !events.isEmpty {
            stateQueue.sync(flags: .barrier) {
                _threatHistory.append(contentsOf: events)
                if _threatHistory.count > _threatHistoryMaxSize {
                    _threatHistory.removeFirst(_threatHistory.count - _threatHistoryMaxSize)
                }
            }
        }

        guard pending.statusChange != nil || !pending.newThreats.isEmpty || !countermeasures.isEmpty else { return }
        DispatchQueue.main.async {
            // Countermeasures fire on main thread so UI work is safe
            for cm in countermeasures {
                let targets = cm.throttled ? pending.newThreats : pending.currentThreats
                for threat in targets where cm.matches(threat) {
                    cm.action(threat)
                }
            }

            if let status = pending.statusChange {
                statusHandler?(status)
            }
            for (threat, event) in zip(pending.newThreats, events) {
                threatHandler?(threat)
                threatEventHandler?(event)
            }
        }
    }

    private func mapToStatus(_ result: SecurityResult) -> SecurityStatus {
        if result.isSecure { return .secure }

        if result.isJailbroken              { return .jailbroken }
        if result.isReverseEngineered       { return .reverseEngineered }
        if result.isAppIntegrityCompromised { return .appIntegrityCompromised }
        if result.isFunctionHooked          { return .hooked }
        if result.isMethodSwizzled          { return .methodSwizzled }
        if result.isFridaDetected           { return .fridaDetected }
        if result.isAttestationFailed       { return .attestationFailed }
        if result.isDSKTampered             { return .dskTampered }
        if result.isDylibInjected           { return .dylibInjection }
        if result.isRepackaged              { return .repackaged }
        if result.isPinningBypassed         { return .pinningBypassed }
        // High
        if result.isDebuggerAttached        { return .debuggerAttached }
        if result.isScreenRecorded          { return .screenRecording }
        // Medium
        if result.isEmulator                { return .emulator }
        if result.isVPNDetected              { return .vpnDetected }
        if result.isProxyDetected            { return .proxyDetected }
        if result.isScreenshotTaken         { return .screenshotTaken }

        return .compromised
    }
}
