//
//  DeviceSecurityConfiguration.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation

public struct DeviceSecurityConfiguration: Equatable {
    public var jailbreakCheckEnabled: Bool
    public var debuggerCheckEnabled: Bool
    public var emulatorCheckEnabled: Bool
    public var reverseEngineeringCheckEnabled: Bool
    public var appIntegrityCheckEnabled: Bool
    public var expectedTeamID: String?
    public var screenRecordingCheckEnabled: Bool
    public var hookDetectionEnabled: Bool
    public var pinningBypassDetectionEnabled: Bool
    public var vpnProxyDetectionEnabled: Bool
    public var allowedVPNBundleIDs: [String]
    public var swizzlingDetectionEnabled: Bool
    public var fridaDetectionEnabled: Bool
    public var attestationCheckEnabled: Bool

    public init(
        jailbreakCheckEnabled: Bool = true,
        debuggerCheckEnabled: Bool = true,
        emulatorCheckEnabled: Bool = true,
        reverseEngineeringCheckEnabled: Bool = true,
        appIntegrityCheckEnabled: Bool = true,
        expectedTeamID: String? = nil,
        screenRecordingCheckEnabled: Bool = true,
        hookDetectionEnabled: Bool = true,
        pinningBypassDetectionEnabled: Bool = true,
        vpnProxyDetectionEnabled: Bool = true,
        allowedVPNBundleIDs: [String] = [],
        swizzlingDetectionEnabled: Bool = true,
        fridaDetectionEnabled: Bool = true,
        attestationCheckEnabled: Bool = false
    ) {
        self.jailbreakCheckEnabled = jailbreakCheckEnabled
        self.debuggerCheckEnabled = debuggerCheckEnabled
        self.emulatorCheckEnabled = emulatorCheckEnabled
        self.reverseEngineeringCheckEnabled = reverseEngineeringCheckEnabled
        self.appIntegrityCheckEnabled = appIntegrityCheckEnabled
        self.expectedTeamID = expectedTeamID
        self.screenRecordingCheckEnabled = screenRecordingCheckEnabled
        self.hookDetectionEnabled = hookDetectionEnabled
        self.pinningBypassDetectionEnabled = pinningBypassDetectionEnabled
        self.vpnProxyDetectionEnabled = vpnProxyDetectionEnabled
        self.allowedVPNBundleIDs = allowedVPNBundleIDs
        self.swizzlingDetectionEnabled = swizzlingDetectionEnabled
        self.fridaDetectionEnabled = fridaDetectionEnabled
        self.attestationCheckEnabled = attestationCheckEnabled
    }
    
    // MARK: - Presets
    
    public static let `default` = DeviceSecurityConfiguration()
    
    public static let jailbreakOnly = DeviceSecurityConfiguration(
        jailbreakCheckEnabled: true,
        debuggerCheckEnabled: false,
        emulatorCheckEnabled: false,
        reverseEngineeringCheckEnabled: false
    )
    
    public static let production = DeviceSecurityConfiguration(
        jailbreakCheckEnabled: true,
        debuggerCheckEnabled: true,
        emulatorCheckEnabled: true,
        reverseEngineeringCheckEnabled: true
    )
    
    public static let disabled = DeviceSecurityConfiguration(
        jailbreakCheckEnabled: false,
        debuggerCheckEnabled: false,
        emulatorCheckEnabled: false,
        reverseEngineeringCheckEnabled: false,
        appIntegrityCheckEnabled: false
    )
    
    // MARK: - Builder Pattern
    
    public func withJailbreakCheck(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.jailbreakCheckEnabled = enabled
        return config
    }
    
    public func withDebuggerCheck(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.debuggerCheckEnabled = enabled
        return config
    }
    
    public func withEmulatorCheck(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.emulatorCheckEnabled = enabled
        return config
    }
    
    public func withReverseEngineeringCheck(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.reverseEngineeringCheckEnabled = enabled
        return config
    }

    public func withScreenRecordingCheck(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.screenRecordingCheckEnabled = enabled
        return config
    }

    public func withHookDetection(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.hookDetectionEnabled = enabled
        return config
    }

    public func withPinningBypassDetection(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.pinningBypassDetectionEnabled = enabled
        return config
    }

    public func withVPNProxyDetection(_ enabled: Bool, allowedBundleIDs: [String]? = nil) -> DeviceSecurityConfiguration {
        var config = self
        config.vpnProxyDetectionEnabled = enabled
        if let ids = allowedBundleIDs {
            config.allowedVPNBundleIDs = ids
        }
        return config
    }

    public func withAppIntegrityCheck(_ enabled: Bool, expectedTeamID: String? = nil) -> DeviceSecurityConfiguration {
        var config = self
        config.appIntegrityCheckEnabled = enabled
        config.expectedTeamID = expectedTeamID
        return config
    }

    public func withSwizzlingDetection(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.swizzlingDetectionEnabled = enabled
        return config
    }

    public func withFridaDetection(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.fridaDetectionEnabled = enabled
        return config
    }

    public func withAttestationCheck(_ enabled: Bool) -> DeviceSecurityConfiguration {
        var config = self
        config.attestationCheckEnabled = enabled
        return config
    }
}
