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

    @Published public private(set) var status: SecurityStatus
    @Published public private(set) var threatHistory: [ThreatEvent]

    private let dsk: DSK
    private var statusTask: Task<Void, Never>?
    private var threatEventTask: Task<Void, Never>?

    /// - Parameter dsk: The `DSK` instance to observe. Defaults to `DSK.shared`.
    public init(dsk: DSK = .shared) {
        self.dsk = dsk
        self.status = dsk.status
        self.threatHistory = dsk.threatHistory

        statusTask = Task { [weak self] in
            guard let self else { return }
            for await status in dsk.statusUpdates {
                self.status = status
            }
        }

        threatEventTask = Task { [weak self] in
            guard let self else { return }
            for await _ in dsk.threatEvents {
                self.threatHistory = dsk.threatHistory
            }
        }
    }

    deinit {
        statusTask?.cancel()
        threatEventTask?.cancel()
    }
}
