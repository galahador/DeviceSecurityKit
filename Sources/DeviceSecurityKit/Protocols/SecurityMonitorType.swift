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
    
    func performCheck() -> SecurityResult
    
    func isSecure() -> Bool
    
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

    // MARK: - Async
    @available(iOS 15.0, *)
    func performCheckAsync() async -> SecurityResult
    @available(iOS 15.0, *)
    func isSecureAsync() async -> Bool
}
