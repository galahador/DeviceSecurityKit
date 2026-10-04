//
//  DSKObservable.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 08/06/2026.
//

import Foundation
import Combine

@available(iOS 15.0, *)
@MainActor
public final class DSKObservable: ObservableObject {
    
    // MARK: - Public
    @Published public private(set) var status: SecurityStatus
    @Published public private(set) var threatHistory: [ThreatEvent]
    @Published public private(set) var activeThreats: Set<SecurityThreat>
    
    // MARK: - Private Properties
    private let dsk: DSK
    private var statusTask: Task<Void, Never>?
    private var threatEventTask: Task<Void, Never>?
    
    // MARK: - init
    public init(dsk: DSK = .shared) {
        self.dsk = dsk
        self.status = dsk.status
        self.threatHistory = dsk.threatHistory
        self.activeThreats = dsk.currentThreats
        
        statusTask = Task { [weak self] in
            guard let self else { return }
            for await status in dsk.statusUpdates {
                self.status = status
                self.activeThreats = dsk.currentThreats
            }
        }
        
        threatEventTask = Task { [weak self] in
            guard let self else { return }
            for await _ in dsk.threatEvents {
                self.threatHistory = dsk.threatHistory
                self.activeThreats = dsk.currentThreats
            }
        }
    }
    
    deinit {
        statusTask?.cancel()
        threatEventTask?.cancel()
    }
}
