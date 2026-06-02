//
//  ScreenRecordingProvider.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
#if canImport(UIKit)
import UIKit
#endif

public protocol ScreenRecordingProvider: Sendable {
    func isScreenBeingRecorded() -> Bool
}

public struct DefaultScreenRecordingProvider: ScreenRecordingProvider, Sendable {
    public init() {}

    public func isScreenBeingRecorded() -> Bool {
#if canImport(UIKit)
        return UIScreen.main.isCaptured
#else
        return false
#endif
    }
}
