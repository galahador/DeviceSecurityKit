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

    public func scheduleBackgroundCheck(identifier: String, earliestBeginDate: Date = Date(timeIntervalSinceNow: 15 * 60)) {
        let request = BGAppRefreshTaskRequest(identifier: identifier)
        request.earliestBeginDate = earliestBeginDate
        try? BGTaskScheduler.shared.submit(request)
    }

    private func handleBackgroundRefresh(_ task: BGAppRefreshTask, identifier: String) {
        scheduleBackgroundCheck(identifier: identifier)

        let checkTask = Task {
            _ = await self.performCheckAsync()
            task.setTaskCompleted(success: true)
        }

        task.expirationHandler = {
            checkTask.cancel()
        }
    }
}
