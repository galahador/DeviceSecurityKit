//
//  Countermeasure.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

public struct Countermeasure: Equatable, Sendable {

    // MARK: - Trigger
    public enum Trigger: Equatable, Sendable {
        case threat(SecurityThreat)
        case minimumSeverity(ThreatSeverity)
        case anyThreat
    }

    // MARK: - Properties
    public let id: UUID
    public let trigger: Trigger
    public let throttled: Bool
    public let action: @Sendable (SecurityThreat) -> Void

    // MARK: - Init
    public init(
        trigger: Trigger,
        throttled: Bool = true,
        action: @escaping @Sendable (SecurityThreat) -> Void
    ) {
        if case .threat(let t) = trigger {
            assert(t.rawValue != "noThreat", "Countermeasures cannot target .noThreat — it is never emitted.")
        }
        self.id        = UUID()
        self.trigger   = trigger
        self.throttled = throttled
        self.action    = action
    }

    // MARK: - Equatable
    public static func == (lhs: Countermeasure, rhs: Countermeasure) -> Bool {
        lhs.id == rhs.id
    }

    // MARK: - Internal

    internal func matches(_ threat: SecurityThreat) -> Bool {
        switch trigger {
        case .threat(let t):          return threat == t
        case .minimumSeverity(let m): return threat.severity >= m
        case .anyThreat:              return true
        }
    }
}
