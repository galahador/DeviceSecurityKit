//
//  DetectorDiagnostic.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

/// Timing and completion information for a single detector run, captured
/// during the most recent `gatherThreats()` pass.
public struct DetectorDiagnostic: Equatable, Codable, Sendable {
    public let duration: TimeInterval

    public let timedOut: Bool

    public init(duration: TimeInterval, timedOut: Bool) {
        self.duration = duration
        self.timedOut = timedOut
    }
}
