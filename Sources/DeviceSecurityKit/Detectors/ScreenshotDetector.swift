//
//  ScreenshotDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 30/05/2026.
//

import Foundation
import UIKit

internal final class ScreenshotDetector {

    // MARK: - Private Properties
    private static let logger = SecurityLogger.security(subsystem: "ScreenshotDetector")
    private static let stateQueue = DispatchQueue(label: "com.devicesecuritykit.screenshot.state", attributes: .concurrent)
    private static var _isObserving = false
    private static var _screenshotDetected = false
    private static var _lastScreenshotDate: Date?
    private static var _screenshotWindowSeconds: TimeInterval = 10

    // MARK: - Public
    static func wasScreenshotTaken() -> Bool {
        return stateQueue.sync {
            guard _screenshotDetected, let lastDate = _lastScreenshotDate else { return false }
            if Date().timeIntervalSince(lastDate) > _screenshotWindowSeconds {
                return false
            }
            return true
        }
    }

    static var detectionWindowSeconds: TimeInterval {
        get { stateQueue.sync { _screenshotWindowSeconds } }
        set { stateQueue.sync(flags: .barrier) { _screenshotWindowSeconds = newValue } }
    }

    static func startObserving() {
        let alreadyObserving = stateQueue.sync(flags: .barrier) { () -> Bool in
            if _isObserving { return true }
            _isObserving = true
            return false
        }
        guard !alreadyObserving else { return }

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleScreenshot),
            name: UIApplication.userDidTakeScreenshotNotification,
            object: nil
        )
    }

    static func stopObserving() {
        stateQueue.sync(flags: .barrier) {
            _isObserving = false
            _screenshotDetected = false
            _lastScreenshotDate = nil
        }

        NotificationCenter.default.removeObserver(
            self,
            name: UIApplication.userDidTakeScreenshotNotification,
            object: nil
        )
    }

    // MARK: - Private
    @objc private static func handleScreenshot() {
        logger.warning("Screenshot detected")
        stateQueue.sync(flags: .barrier) {
            _screenshotDetected = true
            _lastScreenshotDate = Date()
        }
    }
}
