//
//  SecurityMonitor.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

public final class SecurityMonitor: SecurityMonitorType {

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
    private var _screenRecordingProvider: ScreenRecordingProvider? = DefaultScreenRecordingProvider()
    private var _countermeasures: [Countermeasure] = []

    // MARK: - Public Properties
    public var status: SecurityStatus {
        stateQueue.sync { _status }
    }

    public var monitoringInterval: TimeInterval = 60.0

    public var threatCallbackThrottleInterval: TimeInterval {
        get { stateQueue.sync { _threatCallbackThrottleInterval } }
        set { stateQueue.sync(flags: .barrier) { _threatCallbackThrottleInterval = newValue } }
    }

    public var screenRecordingProvider: ScreenRecordingProvider? {
        get { stateQueue.sync { _screenRecordingProvider } }
        set { stateQueue.sync(flags: .barrier) { _screenRecordingProvider = newValue } }
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
        firePending(pending)
        return result
    }

    public func isSecure() -> Bool {
        return performCheck().isSecure
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

        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.schedule(
            deadline: .now() + monitoringInterval,
            repeating: monitoringInterval
        )

        timer.setEventHandler { [weak self] in
            self?.runChecks()
        }

        timer.resume()
        timerQueue.sync { monitoringTimer = timer }
    }

    public func stopMonitoring() {
        timerQueue.sync {
            monitoringTimer?.cancel()
            monitoringTimer = nil
        }
        // Bug 6 fix: write needs .barrier.
        stateQueue.sync(flags: .barrier) { isMonitoring = false }
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
        firePending(pending)
    }

    private func gatherThreats() -> SecurityResult {
        let (cfg, provider) = stateQueue.sync { (configuration, _screenRecordingProvider) }
        var threats: [SecurityThreat] = []
        var evidence: [SecurityThreat: [String]] = [:]

        if cfg.jailbreakCheckEnabled && JailbreakDetector.isJailbroken() {
            threats.append(.jailbreak)
            evidence[.jailbreak] = JailbreakDetector.getDetectionDetails()
        }
        if cfg.debuggerCheckEnabled && DebuggerDetector.isDebuggerAttached() {
            threats.append(.debugger)
            let results = DebuggerDetector.getDetectionResults()
            evidence[.debugger] = results.filter { $0.value }.map { $0.key }
        }
        #if !DEBUG
        if cfg.emulatorCheckEnabled {
            let result = EmulatorDetector.detectEmulator()
            if result.isEmulator {
                threats.append(.emulator)
                evidence[.emulator] = result.detectionMethods
            }
        }
        #endif
        if cfg.reverseEngineeringCheckEnabled && ReverseEngineeringDetector.isReverseEngineered() {
            threats.append(.reverseEngineering)
            evidence[.reverseEngineering] = ["reverseEngineeringToolDetected"]
        }
        if cfg.appIntegrityCheckEnabled && AppIntegrityDetector.isIntegrityCompromised(expectedTeamID: cfg.expectedTeamID) {
            threats.append(.appIntegrity)
            evidence[.appIntegrity] = ["integrityCheckFailed"]
        }
        if cfg.screenRecordingCheckEnabled,
           let provider,
           provider.isScreenBeingRecorded() {
            threats.append(.screenRecording)
            evidence[.screenRecording] = ["screenBeingRecorded"]
        }
        if cfg.hookDetectionEnabled && HookDetector.isFunctionHooked() {
            threats.append(.hooked)
            evidence[.hooked] = HookDetector.collectEvidence()
        }
        if cfg.pinningBypassDetectionEnabled && CertificatePinningDetector.isPinningBypassed() {
            threats.append(.pinningBypassed)
            evidence[.pinningBypassed] = ["pinningBypassDetected"]
        }
        if cfg.vpnProxyDetectionEnabled {
            if VPNProxyDetector.isVPNActive(allowedVPNBundleIDs: cfg.allowedVPNBundleIDs) {
                threats.append(.vpnDetected)
                evidence[.vpnDetected] = ["vpnConnectionActive"]
            }
            if VPNProxyDetector.isProxyActive() {
                threats.append(.proxyDetected)
                evidence[.proxyDetected] = ["proxyConfigured"]
            }
        }
        if cfg.swizzlingDetectionEnabled && SwizzlingDetector.isSwizzled() {
            threats.append(.methodSwizzling)
            evidence[.methodSwizzling] = ["methodSwizzlingDetected"]
        }
        if cfg.fridaDetectionEnabled && FridaDetector.isFridaDetected(portScanEnabled: cfg.fridaPortScanEnabled, ports: cfg.fridaPorts) {
            threats.append(.fridaDetected)
            evidence[.fridaDetected] = FridaDetector.collectEvidence(portScanEnabled: cfg.fridaPortScanEnabled, ports: cfg.fridaPorts)
        }
        if cfg.attestationCheckEnabled && AttestationDetector.isAttestationFailed() {
            threats.append(.attestationFailed)
            evidence[.attestationFailed] = ["attestationFailed"]
        }
        if DSKIntegrityChecker.isDSKCompromised() {
            threats.append(.dskTampered)
            evidence[.dskTampered] = ["dskIntegrityCheckFailed"]
        }
        if cfg.antiRepackagingEnabled && RepackagingDetector.isRepackaged(expectedCertificateHash: cfg.expectedCertificateHash) {
            threats.append(.repackaged)
            evidence[.repackaged] = ["signingCertificateMismatch"]
        }
        if cfg.screenshotDetectionEnabled && ScreenshotDetector.wasScreenshotTaken() {
            threats.append(.screenshotTaken)
            evidence[.screenshotTaken] = ["screenshotDetectedInWindow"]
        }
        if cfg.dylibInjectionDetectionEnabled && DylibInjectionDetector.isDylibInjected() {
            threats.append(.dylibInjection)
            evidence[.dylibInjection] = DylibInjectionDetector.collectEvidence()
        }

        return SecurityResult(threats: threats, evidence: evidence)
    }

    private func applyResult(_ result: SecurityResult) -> (
        statusChange: SecurityStatus?,
        newThreats: [SecurityThreat],
        currentThreats: [SecurityThreat]
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

        return (statusChange, newThreats, Array(currentThreats))
    }

    private func firePending(_ pending: (
        statusChange: SecurityStatus?,
        newThreats: [SecurityThreat],
        currentThreats: [SecurityThreat]
    )) {
        guard pending.statusChange != nil || !pending.newThreats.isEmpty || !pending.currentThreats.isEmpty else { return }

        let (statusHandler, threatHandler, countermeasures) = stateQueue.sync {
            (_onStatusChange, _onThreatDetected, _countermeasures)
        }

        for cm in countermeasures {
            let targets = cm.throttled ? pending.newThreats : pending.currentThreats
            for threat in targets where cm.matches(threat) {
                cm.action(threat)
            }
        }

        guard pending.statusChange != nil || !pending.newThreats.isEmpty else { return }
        DispatchQueue.main.async {
            if let status = pending.statusChange {
                statusHandler?(status)
            }
            for threat in pending.newThreats {
                threatHandler?(threat)
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
