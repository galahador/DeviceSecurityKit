//
//  DetectorDiagnostic.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

public struct DetectorDiagnostic: Equatable, Codable, Sendable {
    public let duration: TimeInterval

    public let timedOut: Bool

    public init(duration: TimeInterval, timedOut: Bool) {
        self.duration = duration
        self.timedOut = timedOut
    }
}
