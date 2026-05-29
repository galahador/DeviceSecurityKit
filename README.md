# DeviceSecurityKit

<p align="center">
  <img src="https://raw.githubusercontent.com/galahador/DeviceSecurityKit/develop/DSK%20Image.png" width="500" alt="DeviceSecurityKit" />
</p>

---

> Lightweight iOS security detection. Zero dependencies. Always free.

[![Swift 5.9+](https://img.shields.io/badge/Swift-5.9+-F05138?style=flat&logo=swift&logoColor=white)](https://swift.org)
[![iOS 15.0+](https://img.shields.io/badge/iOS-15.0+-000000?style=flat&logo=apple&logoColor=white)](https://developer.apple.com/ios/)
[![MIT License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![SPM Compatible](https://img.shields.io/badge/SPM-compatible-4BC51D?style=flat)](https://swift.org/package-manager/)

Detect jailbreak, debugger, emulator, screen recording, and reverse engineering attempts with a single import.

---

## Features

  | Detection | What it checks |
  |-----------|---------------|                                                                                                                                                         
  | 🔒 **Jailbreak** | Files, sandbox escape, fork capability, URL schemes, symlinks, env vars, preboot paths |
  | 🐛 **Debugger** | `sysctl`, `ptrace`, parent process, timing analysis, breakpoint instructions |                                                                                    
  | 📱 **Emulator** | Confidence-scored multi-signal simulator detection |                                                                                                              
  | 🔧 **Reverse Engineering** | Frida, Substrate, libhooker, env vars, code integrity |                                                                                                
  | 🔏 **App Integrity** | Code signature, provisioning profile, team ID validation |                                                                                                   
  | 🎣 **Hook Detection** | Runtime function hooking via dlsym/dladdr + ARM64 prologue scanning |                                                                                       
  | 🔀 **Method Swizzling** | Objective-C IMP redirection on UIApplication and delegate methods |                                                                                       
  | 🕵️  **Frida Detection** | Loaded libraries, Frida symbols, port 27042 connectivity |                                                                                                 
  | 📹 **Screen Recording** | Active recording/mirroring detection |                                                                                                                    
  | 🔐 **Pinning Bypass** | Certificate pinning bypass detection |                                                                                                                      
  | 🌐 **VPN / Proxy** | Network proxy and VPN detection |                                                                                                                              
  | 🔄 **Monitoring** | Real-time continuous background checks with PT_DENY_ATTACH hardening |  

---
## Installation

### Swift Package Manager (Xcode)

1. **File → Add Package Dependencies**
2. Enter the URL:
   ```
   https://github.com/galahador/DeviceSecurityKit.git
   ```
   
3. Set version: `from: "0.22.0"`

4. Click **Add Package**

### `Package.swift`

```swift
dependencies: [
    .package(url: "https://github.com/galahador/DeviceSecurityKit.git", from: "0.22.0")
]
```

---

## Usage

### Quick Start

The recommended way to use DSK is via `DSK.shared`. Set it up once in `AppDelegate` or your app entry point:

```swift
DSK.shared
    .configure(.production)
    .onThreatDetected { threat in
        print("Threat: \(threat.description) — severity: \(threat.severity)")
    }
    .onStatusChange { status in
        print("Security status: \(status)")
    }
    .start()
```

### Responding to Threats

Use `onThreatDetected` to act on each threat based on its severity:

```swift
DSK.shared
    .onThreatDetected { threat in
        switch threat.severity {
        case .critical:
            // 1. Clear sensitive data first
            AuthManager.shared.clearTokens()
            KeychainManager.shared.wipe()

            // 2. Optionally report to backend / analytics
            Analytics.log("security_threat", ["type": threat.rawValue])

            // 3. Terminate — exit(0) looks like a clean exit to the OS
            exit(0)

        case .high:
            // Show blocking UI, force logout
            showSecurityAlert()

        default:
            // Log and monitor, don't block the user
            break
        }
    }
    .start()
```

### One-Shot Check

```swift
let result = DSK.shared.performCheck()

if result.isSecure {
    // Safe to proceed
} else {
    print(result.threats) // [SecurityThreat]
}
```

---

## Configuration

### Presets

```swift
DSK.shared
    .configure(.default)    // All checks enabled
    .configure(.production) // Jailbreak, debugger, emulator, reverse engineering
    .configure(.jailbreakOnly) // Jailbreak detection only
    .configure(.disabled)   // All checks off
    .start()
```

### Custom — Builder Pattern

Fine-tune exactly which checks run:

```swift
let config = DeviceSecurityConfiguration.default
    .withJailbreakCheck(true)
    .withDebuggerCheck(true)
    .withEmulatorCheck(false)
    .withReverseEngineeringCheck(true)
    .withScreenRecordingCheck(true)
    .withHookDetection(true)
    .withPinningBypassDetection(true)
    .withVPNProxyDetection(false) // disable if your app supports corporate VPN

DSK.shared
    .configure(config)
    .start()
```

### Monitoring Interval

```swift
DSK.shared
    .monitoringInterval(30) // re-check every 30 seconds (default: 60)
    .start()
```

### Respond to any threat Automatic countermeasure

```swift 
  DSK.shared                                                                                                                                                            
      .countermeasure(throttled: false) { threat in
          Analytics.log("dsk_threat", ["type": threat.rawValue])
      }                                                                                                                                                                                 
      .start()

  Pre-built Countermeasure objects

  let cm = Countermeasure(trigger: .threat(.fridaDetected), throttled: true) { _ in
      exit(0)
  }

  DSK.shared                                                                                                                                                                            
      .addCountermeasure(cm)
      .start()                                                                                                                                                                          
                  
  // Remove later if needed
  DSK.shared.removeCountermeasure(cm)
  DSK.shared.removeAllCountermeasures()                                                                                                        
```
  ▎ Throttling: By default, throttled countermeasures fire at most once every 300 seconds per threat type. Set throttled: false to fire on every detection cycle.                       


---

## API Reference

### `SecurityMonitor`

| Method | Returns | Description |
|--------|---------|-------------|
| `performCheck()` | `SecurityResult` | Run all configured checks once |
| `isSecure()` | `Bool` | Quick secure/not-secure check |
| `startMonitoring()` | `Void` | Begin continuous monitoring |
| `stopMonitoring()` | `Void` | Stop continuous monitoring |
| `configure(_:)` | `Void` | Update configuration |
| `onStatusChange(_:)` | `Void` | Callback on status change |
| `onThreatDetected(_:)` | `Void` | Callback on threat detection |

### `SecurityResult`

```swift
result.threats              // [SecurityThreat] — all detected threats
result.isSecure             // Bool
result.isJailbroken         // Bool
result.isDebuggerAttached   // Bool
// ... convenience properties for each threat type
```

### `SecurityThreat`

| Threat | Severity |
|--------|----------|
| `.jailbreak` | 🔴 Critical |
| `.reverseEngineering` | 🔴 Critical |
| `.hooked` | 🔴 Critical |
| `.pinningBypassed` | 🔴 Critical |
| ` .methodSwizzling`| 🔴 Critical |
| `.fridaDetected` | 🔴 Critical |
| `.appIntegrity` | 🔴 Critical |
| `.debugger` | 🟠 High |
| `.screenRecording` | 🟠 High |
| `.emulator` | 🟡 Medium |
| `.vpnProxy` | 🟡 Medium |
| `.noThreat` | ✅ Normal |

### `SecurityStatus`

`.secure` · `.jailbroken` · `.debuggerAttached` · `.emulator` · `.reverseEngineered` · `.screenRecording` · `.hooked` · `.pinningBypassed` · `.vpnProxy` · `.compromised`

### `ThreatSeverity`

`.normal (0)` · `.low (1)` · `.medium (2)` · `.high (3)` · `.critical (4)`

---

## Info.plist Configuration

Add this to enable URL scheme detection. Without it, scheme checks silently return `false` — no crash.

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
    <string>cydia</string>
    <string>sileo</string>
    <string>zbra</string>
    <string>filza</string>
    <string>undecimus</string>
    <string>checkra1n</string>
    <string>taurine</string>
    <string>odyssey</string>
    <string>dopamine</string>
</array>
```

---

## Requirements

- **iOS** 15.0+
- **Swift** 5.9+
- **Xcode** 15.0+

---

## Contributing

Issues and PRs are welcome. Open an issue first for major changes.

## License

[MIT](LICENSE) — Created by [galahador](https://github.com/galahador)

---

**Free & open source. No premium tiers, no subscriptions. Ever.**
