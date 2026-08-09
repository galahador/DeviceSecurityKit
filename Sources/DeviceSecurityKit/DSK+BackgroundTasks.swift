//
//  DSK+BackgroundTasks.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 08/06/2026.
//

import Foundation
import BackgroundTasks

/// Background-refresh integration for running security checks while the app
/// is suspended.
extension DSK {

    private static let backgroundTasksLogger = SecurityLogger.security(subsystem: "DSK+BackgroundTasks")

    @discardableResult
    public func registerBackgroundTask(identifier: String) -> Self {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: identifier, using: nil) { [weak self] task in
            guard let self, let refreshTask = task as? BGAppRefreshTask else {
                task.setTaskCompleted(success: false)
                return
            }
            self.handleBackgroundRefresh(refreshTask, identifier: identifier)
        }
        return self
    }

    @discardableResult
    public func scheduleBackgroundCheck(identifier: String, earliestBeginDate: Date = Date(timeIntervalSinceNow: 15 * 60)) -> Bool {
        let request = BGAppRefreshTaskRequest(identifier: identifier)
        request.earliestBeginDate = earliestBeginDate
        do {
            try BGTaskScheduler.shared.submit(request)
            return true
        } catch {
            Self.backgroundTasksLogger.warning("Failed to submit background task '\(identifier)': \(SecurityLogger.redact(error.localizedDescription))")
            return false
        }
    }

    private func handleBackgroundRefresh(_ task: BGAppRefreshTask, identifier: String) {
        scheduleBackgroundCheck(identifier: identifier)

        let completionLock = NSLock()
        var didComplete = false
        func completeOnce(success: Bool) {
            completionLock.lock()
            defer { completionLock.unlock() }
            guard !didComplete else { return }
            didComplete = true
            task.setTaskCompleted(success: success)
        }

        let checkTask = Task {
            _ = await self.performCheckAsync()
            completeOnce(success: true)
        }

        task.expirationHandler = {
            checkTask.cancel()
            completeOnce(success: false)
        }
    }
}
