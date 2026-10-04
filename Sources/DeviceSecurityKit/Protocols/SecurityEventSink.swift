//
//  SecurityEventSink.swift
//  DeviceSecurityKit
//

import Foundation

public protocol SecurityEventSink: AnyObject, Sendable {
    func threatDetected(_ event: ThreatEvent)
    func statusChanged(to status: SecurityStatus)
    func checkCompleted(_ result: SecurityResult)
}

public extension SecurityEventSink {
    func statusChanged(to status: SecurityStatus) {}
    func checkCompleted(_ result: SecurityResult) {}
}
