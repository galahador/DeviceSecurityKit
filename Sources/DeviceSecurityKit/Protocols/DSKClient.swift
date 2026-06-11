//
//  DSKClient.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

public protocol DSKClient: AnyObject {

    // MARK: - Configuration
    func currentConfiguration() -> DeviceSecurityConfiguration
    @discardableResult func configure(_ configuration: DeviceSecurityConfiguration) -> Self
    @discardableResult func monitoringInterval(_ interval: TimeInterval) -> Self
    @discardableResult func minMonitoringInterval(_ interval: TimeInterval) -> Self
    @discardableResult func maxMonitoringInterval(_ interval: TimeInterval) -> Self
    @discardableResult func screenRecordingProvider(_ provider: ScreenRecordingProvider) -> Self

    // MARK: - Handlers
    @discardableResult func onStatusChange(_ handler: @escaping (SecurityStatus) -> Void) -> Self
    @discardableResult func onThreatDetected(_ handler: @escaping (SecurityThreat) -> Void) -> Self
    @discardableResult func onThreatEvent(_ handler: @escaping (ThreatEvent) -> Void) -> Self
    @discardableResult func threatCallbackThrottleInterval(_ interval: TimeInterval) -> Self

    // MARK: - Countermeasures
    @discardableResult func countermeasure(for threat: SecurityThreat, throttled: Bool, action: @escaping @Sendable (SecurityThreat) -> Void) -> Self
    @discardableResult func countermeasure(forMinimumSeverity severity: ThreatSeverity, throttled: Bool, action: @escaping @Sendable (SecurityThreat) -> Void) -> Self
    @discardableResult func countermeasure(throttled: Bool, action: @escaping @Sendable (SecurityThreat) -> Void) -> Self
    @discardableResult func addCountermeasure(_ countermeasure: Countermeasure) -> Self
    @discardableResult func removeCountermeasure(_ countermeasure: Countermeasure) -> Self
    func removeAllCountermeasures()

    // MARK: - Lifecycle
    func start()
    func stop()

    // MARK: - Accessors
    var status: SecurityStatus { get }

    /// Runs all enabled detectors synchronously and returns the result.
    @discardableResult func performCheck() -> SecurityResult
    var isSecure: Bool { get }
    var threatHistory: [ThreatEvent] { get }
    @discardableResult func threatHistoryMaxSize(_ size: Int) -> Self
    func clearThreatHistory()
    var currentMonitoringInterval: TimeInterval { get }

    /// Timing and timeout information for each detector from the most recent performCheck()
    var lastDetectorDiagnostics: [String: DetectorDiagnostic] { get }

    @available(iOS 15.0, *)
    var threatEvents: AsyncStream<ThreatEvent> { get }

    @available(iOS 15.0, *)
    var statusUpdates: AsyncStream<SecurityStatus> { get }
}
