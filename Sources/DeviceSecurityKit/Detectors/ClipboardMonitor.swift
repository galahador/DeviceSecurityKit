//
//  ClipboardMonitor.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 13/06/2026.
//

import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Monitors the system pasteboard for unexpected changes
public final class ClipboardMonitor {

    private static let logger = SecurityLogger.security(subsystem: "ClipboardMonitor")
    private static let stateQueue = DispatchQueue(label: "com.devicesecuritykit.clipboard.state", attributes: .concurrent)

    private static var _isObserving = false
    private static var _lastKnownChangeCount: Int?
    private static var _sensitiveCopyChangeCount: Int?
    private static var _externalChangeDetected = false
    private static var _lastExternalChangeDate: Date?
    private static var _detectionWindowSeconds: TimeInterval = 10

    // MARK: - Public

    /// Call immediately after copying sensitive data
    public static func markSensitiveCopy() {
#if canImport(UIKit)
        let count = UIPasteboard.general.changeCount
        stateQueue.sync(flags: .barrier) {
            _sensitiveCopyChangeCount = count
            _lastKnownChangeCount = count
            _externalChangeDetected = false
            _lastExternalChangeDate = nil
        }
#endif
    }

    public static var detectionWindowSeconds: TimeInterval {
        get { stateQueue.sync { _detectionWindowSeconds } }
        set { stateQueue.sync(flags: .barrier) { _detectionWindowSeconds = newValue } }
    }

    /// Returns true if the pasteboard changed unexpectedly
    static func wasClipboardModifiedExternally() -> Bool {
        return stateQueue.sync {
            guard _externalChangeDetected, let lastDate = _lastExternalChangeDate else { return false }
            if Date().timeIntervalSince(lastDate) > _detectionWindowSeconds {
                return false
            }
            return true
        }
    }

    static func collectEvidence() -> [String] {
        return wasClipboardModifiedExternally() ? ["clipboardChangedAfterSensitiveCopy"] : []
    }

    /// Starts observing `UIPasteboard.changedNotification`. Safe to call multiple times.
    static func startObserving() {
        let alreadyObserving = stateQueue.sync(flags: .barrier) { () -> Bool in
            if _isObserving { return true }
            _isObserving = true
#if canImport(UIKit)
            _lastKnownChangeCount = UIPasteboard.general.changeCount
#endif
            return false
        }
        guard !alreadyObserving else { return }

#if canImport(UIKit)
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handlePasteboardChange),
            name: UIPasteboard.changedNotification,
            object: nil
        )
#endif
    }

    /// Stops observing and clears detection state.
    static func stopObserving() {
        stateQueue.sync(flags: .barrier) {
            _isObserving = false
            _lastKnownChangeCount = nil
            _sensitiveCopyChangeCount = nil
            _externalChangeDetected = false
            _lastExternalChangeDate = nil
        }

#if canImport(UIKit)
        NotificationCenter.default.removeObserver(
            self,
            name: UIPasteboard.changedNotification,
            object: nil
        )
#endif
    }

    // MARK: - Private

#if canImport(UIKit)
    @objc private static func handlePasteboardChange() {
        let currentCount = UIPasteboard.general.changeCount
        stateQueue.sync(flags: .barrier) {
            defer { _lastKnownChangeCount = currentCount }
            guard let last = _lastKnownChangeCount, currentCount != last else { return }
            guard let sensitiveCount = _sensitiveCopyChangeCount, currentCount != sensitiveCount else { return }
            logger.warning("Clipboard contents changed unexpectedly after a sensitive copy")
            _externalChangeDetected = true
            _lastExternalChangeDate = Date()
        }
    }
#endif
}
