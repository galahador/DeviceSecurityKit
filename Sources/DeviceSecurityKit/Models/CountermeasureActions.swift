//
//  CountermeasureActions.swift
//  DeviceSecurityKit
//
//  Created by tBug on 12/09/2026.
//

import Darwin
import Security
import UIKit

// MARK: - Built-in Countermeasures

public extension Countermeasure {
    
    /// Terminates the app immediately.
    static func killApp(trigger: Trigger = .anyThreat,
                        throttled: Bool = true) -> Countermeasure {
        Countermeasure(trigger: trigger, throttled: throttled) { _ in
            exit(0)
        }
    }
    
    /// Deletes every Keychain item owned by the app across all standard item classes.
    static func wipeKeychain(trigger: Trigger = .anyThreat,
                             throttled: Bool = true,
                             accessGroup: String? = nil) -> Countermeasure {
        Countermeasure(trigger: trigger, throttled: throttled) { _ in
            KeychainWiper.wipeAll(accessGroup: accessGroup)
        }
    }
    
    /// Covers every connected window with a blur overlay to hide sensitive content.
    @available(iOS 15.0, *)
    static func blurWindow(trigger: Trigger = .anyThreat,
                           throttled: Bool = true,
                           style: UIBlurEffect.Style = .systemMaterialDark) -> Countermeasure {
        Countermeasure(trigger: trigger, throttled: throttled) { _ in
            DispatchQueue.main.async {
                BlurOverlay.show(style: style)
            }
        }
    }
}

// MARK: - Keychain Wiper

internal enum KeychainWiper {
    private static let secClasses: [CFString] = [kSecClassGenericPassword,
                                                 kSecClassInternetPassword,
                                                 kSecClassCertificate,
                                                 kSecClassKey,
                                                 kSecClassIdentity]
    
    internal static func wipeAll(accessGroup: String? = nil) {
        for secClass in secClasses {
            var query: [String: Any] = [kSecClass as String: secClass]
            if let accessGroup {
                query[kSecAttrAccessGroup as String] = accessGroup
            }
            SecItemDelete(query as CFDictionary)
        }
    }
}

// MARK: - Blur Overlay

@available(iOS 15.0, *)
internal enum BlurOverlay {
    private static let overlayTag = 979_797
    
    /// Adds a blur overlay to every window of every connected scene. Must run on the main thread.
    internal static func show(style: UIBlurEffect.Style) {
        for scene in UIApplication.shared.connectedScenes {
            guard let windowScene = scene as? UIWindowScene else { continue }
            for window in windowScene.windows {
                guard window.viewWithTag(overlayTag) == nil else { continue }
                let blurView = UIVisualEffectView(effect: UIBlurEffect(style: style))
                blurView.tag = overlayTag
                blurView.frame = window.bounds
                blurView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
                window.addSubview(blurView)
            }
        }
    }
}
