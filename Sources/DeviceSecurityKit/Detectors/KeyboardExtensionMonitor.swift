//
//  KeyboardExtensionMonitor.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 13/06/2026.
//

import Foundation
import UIKit

/// Flags third-party keyboard extensions active while a sensitive field is being edited
public final class KeyboardExtensionMonitor {

    private static let logger = SecurityLogger.security(subsystem: "KeyboardExtensionMonitor")
    private static let stateQueue = DispatchQueue(label: "com.devicesecuritykit.keyboardextension.state", attributes: .concurrent)
    private static let o = StringObfuscator.shared

    // "com.apple."
    private static let appleInputModePrefix = o.reveal([0x96, 0x9B, 0x2E, 0x5C, 0x6C, 0x67, 0xE4, 0xE2, 0x98, 0x0A, 0xCA, 0x42, 0x70, 0x25])
    // "identifier"
    private static let identifierKey = o.reveal([0xD6, 0xC8, 0x03, 0x36, 0x8F, 0x1B, 0x87, 0x85, 0xB0, 0x9C, 0x6B, 0xF4, 0x09, 0x04])

    private static var _isObserving = false
    private static var _sensitiveFieldActive = false
    private static var _thirdPartyKeyboardDetected = false
    private static var _lastDetectionDate: Date?
    private static var _detectionWindowSeconds: TimeInterval = 10
    private static weak var _activeResponder: UIResponder?

    // MARK: - Public

    public static var detectionWindowSeconds: TimeInterval {
        get { stateQueue.sync { _detectionWindowSeconds } }
        set { stateQueue.sync(flags: .barrier) { _detectionWindowSeconds = newValue } }
    }

    /// Call when a sensitive field (password, OTP, payment, etc.) becomes the first responder.
    public static func markSensitiveFieldActive(_ responder: UIResponder) {
        stateQueue.sync(flags: .barrier) {
            _sensitiveFieldActive = true
            _activeResponder = responder
        }
        checkActiveKeyboard()
    }

    /// Call when the sensitive field resigns first responder / editing ends.
    public static func markSensitiveFieldInactive() {
        stateQueue.sync(flags: .barrier) {
            _sensitiveFieldActive = false
            _activeResponder = nil
        }
    }

    /// Returns true if a third-party keyboard was detected active on a sensitive field within the detection window.
    static func isThirdPartyKeyboardActive() -> Bool {
        return stateQueue.sync {
            guard _thirdPartyKeyboardDetected, let lastDate = _lastDetectionDate else { return false }
            if Date().timeIntervalSince(lastDate) > _detectionWindowSeconds {
                return false
            }
            return true
        }
    }

    static func collectEvidence() -> [String] {
        return isThirdPartyKeyboardActive() ? ["thirdPartyKeyboardActiveOnSensitiveField"] : []
    }

    /// Starts observing keyboard switches while a sensitive field is active. Safe to call multiple times.
    static func startObserving() {
        let alreadyObserving = stateQueue.sync(flags: .barrier) { () -> Bool in
            if _isObserving { return true }
            _isObserving = true
            return false
        }
        guard !alreadyObserving else { return }

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleInputModeChange),
            name: UITextInputMode.currentInputModeDidChangeNotification,
            object: nil
        )
    }

    /// Stops observing and clears detection state.
    static func stopObserving() {
        stateQueue.sync(flags: .barrier) {
            _isObserving = false
            _sensitiveFieldActive = false
            _thirdPartyKeyboardDetected = false
            _lastDetectionDate = nil
            _activeResponder = nil
        }

        NotificationCenter.default.removeObserver(self, name: UITextInputMode.currentInputModeDidChangeNotification, object: nil)
    }

    // MARK: - Private

    @objc private static func handleInputModeChange() {
        checkActiveKeyboard()
    }

    private static func checkActiveKeyboard() {
        let (isActive, responder) = stateQueue.sync { (_sensitiveFieldActive, _activeResponder) }
        guard isActive, let responder = responder, let inputMode = responder.textInputMode else { return }

        guard let identifier = inputMode.value(forKey: identifierKey) as? String else { return }
        if !identifier.hasPrefix(appleInputModePrefix) {
            logger.warning("Third-party keyboard active on a sensitive field")
            stateQueue.sync(flags: .barrier) {
                _thirdPartyKeyboardDetected = true
                _lastDetectionDate = Date()
            }
        }
    }
}
