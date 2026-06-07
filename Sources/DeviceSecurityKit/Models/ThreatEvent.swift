//
//  ThreatEvent.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

public struct ThreatEvent: Hashable, Codable, Sendable {
    public let threat: SecurityThreat
    public let severity: ThreatSeverity
    public let detectedAt: Date
    public let evidence: [String]

    public init(
        threat: SecurityThreat,
        severity: ThreatSeverity,
        detectedAt: Date,
        evidence: [String]
    ) {
        self.threat = threat
        self.severity = severity
        self.detectedAt = detectedAt
        self.evidence = evidence
    }
}
