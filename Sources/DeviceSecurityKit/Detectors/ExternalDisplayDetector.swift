//
//  ExternalDisplayDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 13/06/2026.
//

import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Detects an external display connection (AirPlay screen mirroring, wired/wireless external monitors)
internal final class ExternalDisplayDetector {

    private static let logger = SecurityLogger.security(subsystem: "ExternalDisplayDetector")
    private static let stateQueue = DispatchQueue(label: "com.devicesecuritykit.externaldisplay.state", attributes: .concurrent)

    private static var _isObserving = false

    // MARK: - Public

    /// Returns true if any screen besides `UIScreen.main` is currently connected to AirPlay mirroring
    static func isExternalDisplayConnected() -> Bool {
#if canImport(UIKit)
        return UIScreen.screens.count > 1
#else
        return false
#endif
    }

    static func collectEvidence() -> [String] {
        return isExternalDisplayConnected() ? ["externalDisplayConnected"] : []
    }

    static func startObserving() {
        let alreadyObserving = stateQueue.sync(flags: .barrier) { () -> Bool in
            if _isObserving { return true }
            _isObserving = true
            return false
        }
        guard !alreadyObserving else { return }

#if canImport(UIKit)
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleScreenChange),
            name: UIScreen.didConnectNotification,
            object: nil
        )
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleScreenChange),
            name: UIScreen.didDisconnectNotification,
            object: nil
        )
#endif
    }

    /// Stops observing.
    static func stopObserving() {
        stateQueue.sync(flags: .barrier) {
            _isObserving = false
        }

#if canImport(UIKit)
        NotificationCenter.default.removeObserver(self, name: UIScreen.didConnectNotification, object: nil)
        NotificationCenter.default.removeObserver(self, name: UIScreen.didDisconnectNotification, object: nil)
#endif
    }

    // MARK: - Private

#if canImport(UIKit)
    @objc private static func handleScreenChange() {
        if isExternalDisplayConnected() {
            logger.warning("External display connected — possible AirPlay/screen mirroring")
        }
    }
#endif
}
