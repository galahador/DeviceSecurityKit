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
| 🌐 Pinning Bypass Detection | SSL/TLS interception and delegate integrity validation |
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
from: "0.24.0"
```

4. Add Package

#### Package.swift

```swift
dependencies: [
    .package(
        url: "https://github.com/galahador/DeviceSecurityKit.git",
        from: "0.24.0"
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

Default:

```text
60 seconds
```

---

## 🎯 Countermeasures

```swift
DSK.shared
    .countermeasure(
        throttled: false
    ) { threat in

        Analytics.log(
            "dsk_threat",
            ["type": threat.rawValue]
        )
    }
```

### Custom Countermeasure

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

> ⚠️ Throttled countermeasures execute once every 300 seconds per threat type.

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
