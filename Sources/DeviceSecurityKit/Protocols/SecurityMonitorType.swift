//
//  SecurityMonitorType.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

public protocol SecurityMonitorType {

    var status: SecurityStatus { get }

    var monitoringInterval: TimeInterval { get set }
    var minMonitoringInterval: TimeInterval { get set }
    var maxMonitoringInterval: TimeInterval { get set }
    var currentMonitoringInterval: TimeInterval { get }

    var threatCallbackThrottleInterval: TimeInterval { get set }

    var screenRecordingProvider: ScreenRecordingProvider? { get set }

    @discardableResult func performCheck() -> SecurityResult

    var isSecure: Bool { get }

    func startMonitoring()

    func stopMonitoring()

    func configure(_ configuration: DeviceSecurityConfiguration)

    func currentConfiguration() -> DeviceSecurityConfiguration

    @discardableResult
    func onStatusChange(_ handler: @escaping (SecurityStatus) -> Void) -> Self

    @discardableResult
    func onThreatDetected(_ handler: @escaping (SecurityThreat) -> Void) -> Self

    @discardableResult
    func onThreatEvent(_ handler: @escaping (ThreatEvent) -> Void) -> Self

    @discardableResult
    func addCountermeasure(_ countermeasure: Countermeasure) -> Self

    @discardableResult
    func removeCountermeasure(_ countermeasure: Countermeasure) -> Self

    func removeAllCountermeasures()

    // MARK: - Threat History
    var threatHistory: [ThreatEvent] { get }
    var threatHistoryMaxSize: Int { get set }
    func clearThreatHistory()

    // MARK: - Async
    @available(iOS 15.0, *)
    func performCheckAsync() async -> SecurityResult
    @available(iOS 15.0, *)
    func isSecureAsync() async -> Bool

    @available(iOS 15.0, *)
    var threatEvents: AsyncStream<ThreatEvent> { get }

    @available(iOS 15.0, *)
    var statusUpdates: AsyncStream<SecurityStatus> { get }
}
