//
//  SecurityLogger.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

#if canImport(os.log)
import os.log
#endif

// MARK: - SecurityLogger Manager
public final class SecurityLogger {
    
    // MARK: - Public Types
    
    public enum LogLevel: Int, CaseIterable, Comparable {
        case debug = 0
        case info = 1
        case warning = 2
        case error = 3
        
        public var displayName: String {
            switch self {
            case .debug: return "🔍 DEBUG"
            case .info: return "ℹ️ INFO"
            case .warning: return "⚠️ WARNING"
            case .error: return "❌ ERROR"
            }
        }
        
        internal var osLogType: OSLogType {
            #if canImport(os.log)
            switch self {
            case .debug: return .debug
            case .info: return .info
            case .warning: return .default
            case .error: return .error
            }
            #else
            return .default
            #endif
        }
        
        public static func < (lhs: LogLevel, rhs: LogLevel) -> Bool {
            return lhs.rawValue < rhs.rawValue
        }
    }
    
    // MARK: - Private Properties
    
    private let subsystem: String
    private let category: String
    private let dateFormatter: DateFormatter
    private let loggingQueue = DispatchQueue(label: "SecurityLogger.output", qos: .utility)
    
    #if canImport(os.log)
    @available(iOS 10.0, *)
    private lazy var osLog: OSLog = {
        return OSLog(subsystem: subsystem, category: category)
    }()
    #endif
    
    // MARK: - Initialization
    
    public init(subsystem: String, category: String) {
        self.subsystem = subsystem
        self.category = category
        self.dateFormatter = Self.createDateFormatter()
    }
    
    // MARK: - Public Methods
    
    public func log(
        _ message: String,
        level: LogLevel = .info,
        file: String = #file,
        function: String = #function,
        line: Int = #line
    ) {
        let config = SecurityLoggerManager.shared.currentConfiguration()
        
        // Check if logging is enabled and level is appropriate
        guard config.enableLogging && level >= config.logLevel else { return }
        
        loggingQueue.async { [weak self] in
            self?.performLogging(
                message: message,
                level: level,
                file: file,
                function: function,
                line: line,
                config: config
            )
        }
    }
    
    public func debug(
        _ message: String,
        file: String = #file,
        function: String = #function,
        line: Int = #line
    ) {
        log(message, level: .debug, file: file, function: function, line: line)
    }
    
    public func info(
        _ message: String,
        file: String = #file,
        function: String = #function,
        line: Int = #line
    ) {
        log(message, level: .info, file: file, function: function, line: line)
    }
    
    public func warning(
        _ message: String,
        file: String = #file,
        function: String = #function,
        line: Int = #line
    ) {
        log(message, level: .warning, file: file, function: function, line: line)
    }
    
    public func error(
        _ message: String,
        file: String = #file,
        function: String = #function,
        line: Int = #line
    ) {
        log(message, level: .error, file: file, function: function, line: line)
    }
    
    // MARK: - Private Methods
    
    private static func createDateFormatter() -> DateFormatter {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone.current
        return formatter
    }
    
    private func performLogging(
        message: String,
        level: LogLevel,
        file: String,
        function: String,
        line: Int,
        config: SecurityLoggerConfiguration
    ) {
        let formattedMessage = formatLogMessage(
            message: message,
            level: level,
            file: file,
            function: function,
            line: line
        )
        
        // Custom output handler has highest priority
        if let customHandler = config.customOutputHandler {
            customHandler(formattedMessage, level)
            return
        }
        
        // Console output
        if config.enableConsoleOutput {
            print(formattedMessage)
        }
        
        // System logging
        if config.enableSystemLogging {
            outputToSystem(formattedMessage, level: level)
        }
    }
    
    private func formatLogMessage(
        message: String,
        level: LogLevel,
        file: String,
        function: String,
        line: Int
    ) -> String {
        let fileName = URL(fileURLWithPath: file).lastPathComponent
        let timestamp = dateFormatter.string(from: Date())
        
        return "[\(timestamp)] \(level.displayName) [\(subsystem):\(category)] \(fileName):\(line) \(function) - \(message)"
    }
    
    private func outputToSystem(_ message: String, level: LogLevel) {
        #if canImport(os.log)
        if #available(iOS 10.0, *) {
            os_log("%{public}@", log: osLog, type: level.osLogType, message)
        } else {
            NSLog("%@", message)
        }
        #else
        NSLog("%@", message)
        #endif
    }
}

// MARK: - Convenience Factory

public extension SecurityLogger {
    static func security(subsystem: String) -> SecurityLogger {
        return SecurityLogger(subsystem: subsystem, category: "Security")
    }
    
    static func debug(subsystem: String) -> SecurityLogger {
        return SecurityLogger(subsystem: subsystem, category: "Debug")
    }
    
    static func monitor(subsystem: String) -> SecurityLogger {
        return SecurityLogger(subsystem: subsystem, category: "Monitor")
    }
    
    static func detection(subsystem: String) -> SecurityLogger {
        return SecurityLogger(subsystem: subsystem, category: "Detection")
    }
    
    static func analysis(subsystem: String) -> SecurityLogger {
        return SecurityLogger(subsystem: subsystem, category: "Analysis")
    }
}

// MARK: - Library Internal Helper

internal extension SecurityLogger {
    static func libraryLogger(for component: String) -> SecurityLogger {
        return SecurityLogger(subsystem: "DeviceSecurityKit", category: component)
    }

    /// Redacts sensitive values in release builds.
    /// - DEBUG: returns the full value for developer diagnostics
    /// - RELEASE: returns a short hash prefix so logs remain correlatable without exposing raw data
    static func redact(_ value: String) -> String {
#if DEBUG
        return value
#else
        guard !value.isEmpty else { return "<empty>" }
        // FNV-1a 32-bit hash → 8 hex chars, enough to correlate without exposing the value
        var hash: UInt32 = 0x811c9dc5
        for byte in value.utf8 {
            hash ^= UInt32(byte)
            hash = hash &* 0x01000193
        }
        return "<redacted:\(String(hash, radix: 16))>"
#endif
    }
}
