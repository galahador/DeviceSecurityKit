# 🛡️ DeviceSecurityKit

<p align="center">
  <img src="https://raw.githubusercontent.com/galahador/DeviceSecurityKit/develop/DSK%20Image.png" width="550" alt="DeviceSecurityKit" />
</p>

<p align="center">
  <strong>Lightweight iOS Security Detection Framework</strong>
</p>

<p align="center">
  Detect jailbreaks, debuggers, emulators, Frida, runtime hooks, SSL pinning bypasses, VPN/proxy usage and more.
</p>

<p align="center">

![Swift](https://img.shields.io/badge/Swift-5.9+-F05138?style=for-the-badge&logo=swift&logoColor=white)
![iOS](https://img.shields.io/badge/iOS-15.0+-000000?style=for-the-badge&logo=apple&logoColor=white)
![SPM](https://img.shields.io/badge/SPM-Compatible-4BC51D?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

</p>

---

## 🚀 Features

| Category | Detection |
|-----------|-----------|
| 🔓 Jailbreak | Files, sandbox escape, fork capability, URL schemes, symlinks, environment variables |
| 🐞 Debugger | sysctl, ptrace, parent process, timing analysis, breakpoint instructions |
| 📱 Emulator | Hardware mismatch, simulator artifacts, DeviceCheck validation |
| 🧬 Reverse Engineering | Frida, Substrate, libhooker, runtime tampering |
| 🔒 App Integrity | Code signature validation, Team ID verification, CodeResources hash validation |
| 🪝 Hook Detection | Runtime function hook detection via ARM64 prologue inspection |
| 🔄 Swizzling Detection | Objective-C IMP redirection validation |
| 👾 Frida Detection | Libraries, symbols, process checks, multi-port scanning |
| 📺 Screen Recording | Active recording and mirroring detection |
| 📸 Screenshot Detection | Real-time screenshot notifications |
| 🌐 Pinning Bypass Detection | Detects bypass tools (SSLKillSwitch, ssl-proxy, etc.) and proxy configurations — not a substitute for implementing certificate/public-key pinning in your networking stack |
| 🔌 VPN / Proxy Detection | VPN interfaces and proxy configuration detection |
| 🔐 App Attest | Apple App Attest validation |
| 📦 Anti-Repackaging | Signing certificate verification |
| 🛡️ DSK Integrity | Runtime validation of DSK internals |
| ⏱️ Monitoring | Continuous background security monitoring |

---

## ⚡ Quick Start

```swift
import DeviceSecurityKit

DSK.shared
    .configure(.production)
    .onThreatDetected { threat in
        print("Threat: \(threat.description)")
    }
    .start()
```

---

## 📦 Installation

### Swift Package Manager

#### Xcode

1. File → Add Package Dependencies
2. Enter:

```text
https://github.com/galahador/DeviceSecurityKit.git
```

3. Select:

```text
from: "0.32.0"
```

4. Add Package

#### Package.swift

```swift
dependencies: [
    .package(
        url: "https://github.com/galahador/DeviceSecurityKit.git",
        from: "0.32.0"
    )
]
```

---

## 🎯 Usage

### Configure

```swift
DSK.shared
    .configure(.production)
    .start()
```

### Threat Monitoring

```swift
DSK.shared
    .onThreatDetected { threat in
        print(threat.description)
    }
    .start()
```

### Security Status Monitoring

```swift
DSK.shared
    .onStatusChange { status in
        print(status)
    }
    .start()
```

### One-Shot Security Check

```swift
let result = DSK.shared.performCheck()

if result.isSecure {
    print("Secure")
} else {
    print(result.threats)
}
```

> `performCheck()` runs all enabled detectors synchronously and may take several seconds. Call it off the main thread, or use the async variant below.

### Async API

```swift
let result = await DSK.shared.performCheckAsync()
let secure = await DSK.shared.isSecureAsync()
```

#### App Attest

```swift
let attestation = try await DSK.shared.attest(challengeHash: serverChallenge)
// Send `attestation` to your backend for verification
```

#### AsyncStream

Subscribe to a live stream of threat events:

```swift
Task {
    for await event in DSK.shared.threatEvents {
        print("\(event.threat) at \(event.detectedAt)")
        print("Evidence: \(event.evidence)")
    }
}
```

Multiple consumers can subscribe independently. The stream ends when `stop()` is called or the consuming `Task` is cancelled.

### Threat History

DSK keeps a ring buffer of recent `ThreatEvent`s so you can inspect detections after the fact:

```swift
let history = DSK.shared.threatHistory

for event in history {
    print("\(event.threat) — \(event.detectedAt)")
}
```

Configure the buffer size (default: 100) and clear it:

```swift
DSK.shared
    .threatHistoryMaxSize(200)
    .start()

// Later:
DSK.shared.clearThreatHistory()
```

---

## 🚨 Responding To Threats

```swift
DSK.shared
    .onThreatDetected { threat in

        switch threat.severity {

        case .critical:

            AuthManager.shared.clearTokens()
            KeychainManager.shared.wipe()

            Analytics.log(
                "security_threat",
                ["type": threat.rawValue]
            )

            exit(0)

        case .high:

            showSecurityAlert()

        default:
            break
        }
    }
    .start()
```

---

## ⚙️ Configuration

### Presets

```swift
.configure(.default)
.configure(.production)
.configure(.jailbreakOnly)
.configure(.disabled)
```

### Custom Configuration

```swift
let config = DeviceSecurityConfiguration.default
    .withJailbreakCheck(true)
    .withDebuggerCheck(true)
    .withEmulatorCheck(false)
    .withReverseEngineeringCheck(true)
    .withScreenRecordingCheck(true)
    .withScreenshotDetection(true)
    .withHookDetection(true)
    .withPinningBypassDetection(true)
    .withSwizzlingDetection(true)
    .withFridaDetection(true)
    .withAttestationCheck(true)
    .withVPNProxyDetection(
        true,
        allowedBundleIDs: [
            "com.example.corporate-vpn"
        ]
    )
    .withAppIntegrityCheck(
        true,
        expectedTeamID: "ABCDE12345"
    )
    .withAntiRepackagingCheck(
        true,
        expectedCertificateHash: "a1b2c3..."
    )

DSK.shared
    .configure(config)
    .start()
```

---

## 🔒 Anti-Repackaging

### Obtain Your Certificate Hash

```swift
#if DEBUG
print(
    RepackagingDetector.currentCertificateHash()
)
#endif
```

### Configure

```swift
.withAntiRepackagingCheck(
    true,
    expectedCertificateHash:
    "your-hash-here"
)
```

---

## 🌐 VPN Allowlist

```swift
.withVPNProxyDetection(
    true,
    allowedBundleIDs: [
        "com.cisco.anyconnect",
        "com.microsoft.intune.tunnel"
    ]
)
```

---

## ⏱️ Monitoring Interval

```swift
DSK.shared
    .monitoringInterval(30)
    .start()
```

Default: `60 seconds`

### Adaptive Monitoring

DSK uses exponential backoff to balance responsiveness with efficiency:

- **Threat detected** — interval snaps to `minMonitoringInterval` for rapid re-checking.
- **Consecutive clean cycles** — interval doubles each cycle: `base × 2^cleanCycles`, clamped to `[min, max]`.

```swift
DSK.shared
    .monitoringInterval(60)        // base interval
    .minMonitoringInterval(10)     // fastest re-check
    .maxMonitoringInterval(600)    // slowest backoff
    .start()
```

Query the current adaptive interval at any time:

```swift
let current = DSK.shared.currentMonitoringInterval
```

---

## 🎯 Countermeasures

Countermeasures are automatic actions that fire when a threat is detected.

### Any Threat

```swift
DSK.shared
    .countermeasure(throttled: false) { threat in
        Analytics.log("dsk_threat", ["type": threat.rawValue])
    }
```

### Specific Threat

```swift
DSK.shared
    .countermeasure(for: .jailbreak, throttled: true) { _ in
        AuthManager.shared.clearTokens()
    }
```

### Severity-Based

```swift
DSK.shared
    .countermeasure(forMinimumSeverity: .critical, throttled: true) { threat in
        KeychainManager.shared.wipe()
        exit(0)
    }
```

### Custom Countermeasure Object

```swift
let cm = Countermeasure(
    trigger: .threat(.fridaDetected),
    throttled: true
) { _ in
    exit(0)
}

DSK.shared.addCountermeasure(cm)
```

### Remove Countermeasures

```swift
DSK.shared.removeCountermeasure(cm)
DSK.shared.removeAllCountermeasures()
```

> Throttled countermeasures execute once every 300 seconds per threat type. Adjust with `.threatCallbackThrottleInterval(_:)`.

---

## 📊 Threat Severity

| Severity | Meaning |
|-----------|-----------|
| 🟢 Normal | No threat detected |
| 🔵 Low | Informational |
| 🟡 Medium | Potential risk |
| 🟠 High | Dangerous environment |
| 🔴 Critical | Immediate action recommended |

---

## 📚 API Reference

### SecurityMonitor

| Method | Description |
|----------|----------|
| performCheck() | Run all configured checks |
| isSecure() | Quick security status |
| startMonitoring() | Begin monitoring |
| stopMonitoring() | Stop monitoring |
| configure() | Update configuration |
| onStatusChange() | Status callback |
| onThreatDetected() | Threat callback |

---

## 🚩 Supported Threats

| Threat | Severity |
|---------|----------|
| Jailbreak | 🔴 Critical |
| Reverse Engineering | 🔴 Critical |
| App Integrity Failure | 🔴 Critical |
| Hook Detection | 🔴 Critical |
| Method Swizzling | 🔴 Critical |
| Pinning Bypass | 🔴 Critical |
| Frida | 🔴 Critical |
| Attestation Failure | 🔴 Critical |
| DSK Tampering | 🔴 Critical |
| Repackaging | 🔴 Critical |
| Debugger | 🟠 High |
| Screen Recording | 🟠 High |
| Emulator | 🟡 Medium |
| VPN / Proxy | 🟡 Medium |
| Screenshot | 🟡 Medium |

---

## 📋 Info.plist

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

## 📱 Requirements

| Requirement | Version |
|-------------|----------|
| iOS | 15.0+ |
| Swift | 5.9+ |
| Xcode | 15.0+ |

---

## Limitations

DeviceSecurityKit is a **client-side detection library**. All checks run within the app process on the user's device, which means:

- **Bypassable by a determined attacker.** Anyone with full control of the device (root access, custom kernel, instrumentation frameworks) can intercept, patch, or suppress any check. No client-side security library can prevent this.
- **Best used as a signal, not a gate.** Treat detection results as one input into a broader risk-assessment pipeline. Combine them with server-side validation (App Attest, device posture APIs, backend anomaly detection) for defence in depth.
- **False positives are possible.** Some legitimate developer tools, accessibility software, enterprise MDM profiles, or VPN configurations may trigger detections. Test thoroughly with your user base and use the configuration API to disable checks that don't apply.
- **Simulator environment.** Several detectors are automatically disabled in the iOS Simulator (`#if targetEnvironment(simulator)`) because they would always trigger. Test security-critical flows on a real device.

---

## 🤝 Contributing

Issues and pull requests are welcome.

For major changes, please open an issue first.

---

## 📄 License

MIT License

Created by **@galahador**

---

<p align="center">
<strong>🛡️ Security First • Zero Dependencies • Open Source Forever</strong>
</p>
