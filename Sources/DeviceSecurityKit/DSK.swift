//
//  DSK.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

public final class DSK: DSKClient, @unchecked Sendable {

    // MARK: - Singleton

    public static let shared = DSK()

    // MARK: - Private

    private let monitor = SecurityMonitor()

    private init() {}

    // MARK: - Configuration

    public func currentConfiguration() -> DeviceSecurityConfiguration {
        monitor.currentConfiguration()
    }

    @discardableResult
    public func configure(_ configuration: DeviceSecurityConfiguration = .default) -> Self {
        monitor.configure(configuration)
        return self
    }

    @discardableResult
    public func monitoringInterval(_ interval: TimeInterval) -> Self {
        monitor.monitoringInterval = interval
        return self
    }

    @discardableResult
    public func minMonitoringInterval(_ interval: TimeInterval) -> Self {
        monitor.minMonitoringInterval = interval
        return self
    }

    @discardableResult
    public func maxMonitoringInterval(_ interval: TimeInterval) -> Self {
        monitor.maxMonitoringInterval = interval
        return self
    }

    public var currentMonitoringInterval: TimeInterval {
        monitor.currentMonitoringInterval
    }

    @discardableResult
    public func screenRecordingProvider(_ provider: ScreenRecordingProvider) -> Self {
        monitor.screenRecordingProvider = provider
        return self
    }

    // MARK: - Handlers

    @discardableResult
    public func onStatusChange(_ handler: @escaping (SecurityStatus) -> Void) -> Self {
        monitor.onStatusChange(handler)
        return self
    }

    @discardableResult
    public func onThreatDetected(_ handler: @escaping (SecurityThreat) -> Void) -> Self {
        monitor.onThreatDetected(handler)
        return self
    }

    @discardableResult
    public func onThreatEvent(_ handler: @escaping (ThreatEvent) -> Void) -> Self {
        monitor.onThreatEvent(handler)
        return self
    }

    @discardableResult
    public func threatCallbackThrottleInterval(_ interval: TimeInterval) -> Self {
        monitor.threatCallbackThrottleInterval = interval
        return self
    }

    // MARK: - Countermeasures
    @discardableResult
    public func countermeasure(
        for threat: SecurityThreat,
        throttled: Bool = true,
        action: @escaping @Sendable (SecurityThreat) -> Void
    ) -> Self {
        monitor.addCountermeasure(Countermeasure(trigger: .threat(threat), throttled: throttled, action: action))
        return self
    }

    @discardableResult
    public func countermeasure(
        forMinimumSeverity severity: ThreatSeverity,
        throttled: Bool = true,
        action: @escaping @Sendable (SecurityThreat) -> Void
    ) -> Self {
        monitor.addCountermeasure(Countermeasure(trigger: .minimumSeverity(severity), throttled: throttled, action: action))
        return self
    }

    @discardableResult
    public func countermeasure(
        throttled: Bool = true,
        action: @escaping @Sendable (SecurityThreat) -> Void
    ) -> Self {
        monitor.addCountermeasure(Countermeasure(trigger: .anyThreat, throttled: throttled, action: action))
        return self
    }

    @discardableResult
    public func addCountermeasure(_ countermeasure: Countermeasure) -> Self {
        monitor.addCountermeasure(countermeasure)
        return self
    }

    @discardableResult
    public func removeCountermeasure(_ countermeasure: Countermeasure) -> Self {
        monitor.removeCountermeasure(countermeasure)
        return self
    }

    public func removeAllCountermeasures() {
        monitor.removeAllCountermeasures()
    }

    // MARK: - Lifecycle
    public func start() {
        monitor.startMonitoring()
    }

    public func stop() {
        monitor.stopMonitoring()
    }

    // MARK: - Accessors

    public var status: SecurityStatus {
        return monitor.status
    }

    /// Runs all enabled detectors synchronously and returns the result.
    ///
    /// - Important: This method may take several seconds depending on enabled
    ///   detectors and the configured `detectorTimeout`. **Do not call on the
    ///   main thread** — use `performCheckAsync()` or dispatch to a background
    ///   queue instead.
    @discardableResult
    public func performCheck() -> SecurityResult {
        return monitor.performCheck()
    }

    public var isSecure: Bool {
        return monitor.isSecure
    }

    public var threatHistory: [ThreatEvent] {
        return monitor.threatHistory
    }

    @discardableResult
    public func threatHistoryMaxSize(_ size: Int) -> Self {
        monitor.threatHistoryMaxSize = size
        return self
    }

    public func clearThreatHistory() {
        monitor.clearThreatHistory()
    }

    // MARK: - Async

    @available(iOS 15.0, *)
    public func performCheckAsync() async -> SecurityResult {
        await monitor.performCheckAsync()
    }

    @available(iOS 15.0, *)
    public func isSecureAsync() async -> Bool {
        await monitor.isSecureAsync()
    }

    @available(iOS 15.0, *)
    public func attest(challengeHash: Data) async throws -> Data {
        try await AttestationDetector.attest(challengeHash: challengeHash)
    }

    // MARK: - AsyncStream

    @available(iOS 15.0, *)
    public var threatEvents: AsyncStream<ThreatEvent> {
        monitor.threatEvents
    }

    /// A live stream of `SecurityStatus` changes.
    /// Unlike `onStatusChange`, which holds a single overwritable handler,
    @available(iOS 15.0, *)
    public var statusUpdates: AsyncStream<SecurityStatus> {
        monitor.statusUpdates
    }
}
