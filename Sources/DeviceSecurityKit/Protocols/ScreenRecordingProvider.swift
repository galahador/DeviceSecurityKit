//
//  ScreenRecordingProvider.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
import UIKit

public protocol ScreenRecordingProvider: Sendable {
    func isScreenBeingRecorded() -> Bool
}

public struct DefaultScreenRecordingProvider: ScreenRecordingProvider, Sendable {
    public init() {}

    public func isScreenBeingRecorded() -> Bool {
        return UIScreen.main.isCaptured
    }
}
