//
//  SecurityEventSink.swift
//  DeviceSecurityKit
//

import Foundation

public protocol SecurityEventSink: AnyObject, Sendable {

    /// Called for each new threat event (throttled — same cadence as `onThreatEvent`).
    func threatDetected(_ event: ThreatEvent)

    /// Called each time the overall device security status changes.

    func statusChanged(to status: SecurityStatus)

    /// Receives the full `SecurityResult` including `riskScore` and `riskLevel`,
    func checkCompleted(_ result: SecurityResult)
}

public extension SecurityEventSink {
    func statusChanged(to status: SecurityStatus) {}
    func checkCompleted(_ result: SecurityResult) {}
}
