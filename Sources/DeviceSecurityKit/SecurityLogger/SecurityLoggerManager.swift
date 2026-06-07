//
//  SecurityLoggerManager.swift
//  DeviceSecurityKit
//
//  Created by tBug on 17. 2. 2026..
//

import Foundation

public final class SecurityLoggerManager {
    public static let shared = SecurityLoggerManager()
    
    private var configuration: SecurityLoggerConfiguration = .default
    private let configurationQueue = DispatchQueue(label: "SecurityLogger.config", qos: .utility, attributes: .concurrent)
    
    private init() {}
    
    public func configure(_ configuration: SecurityLoggerConfiguration) {
        configurationQueue.sync(flags: .barrier) {
            self.configuration = configuration
        }
    }
    
    internal func currentConfiguration() -> SecurityLoggerConfiguration {
        return configurationQueue.sync {
            return configuration
        }
    }
}
