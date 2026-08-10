//
//  AttestationDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
#if os(iOS)
import DeviceCheck
#endif

public final class AttestationDetector {

    private static let logger = SecurityLogger.security(subsystem: "AttestationDetector")

    // MARK: - State

    private static let stateQueue = DispatchQueue(
        label: "com.devicesecuritykit.attestation.state",
        attributes: .concurrent
    )
    private static let persistenceQueue = DispatchQueue(
        label: "com.devicesecuritykit.attestation.persistence"
    )
    private static var _hasAttempted = false
    private static var _hasFailed    = false
    private static var _persistenceEnabled = false

    public static var persistenceEnabled: Bool {
        get { stateQueue.sync { _persistenceEnabled } }
        set {
            let shouldLoad = stateQueue.sync(flags: .barrier) { () -> Bool in
                let wasEnabled = _persistenceEnabled
                _persistenceEnabled = newValue
                return newValue && !wasEnabled && !_hasAttempted
            }
            guard shouldLoad, let persisted = AttestationStateStore.shared.load() else { return }
            stateQueue.sync(flags: .barrier) {
                _hasAttempted = persisted.hasAttempted
                _hasFailed    = persisted.hasFailed
            }
        }
    }

    // MARK: - Public – synchronous check (reads cached state)

    public static func isAttestationFailed() -> Bool {
#if os(iOS)
        guard DCAppAttestService.shared.isSupported else { return false }
        return stateQueue.sync { _hasAttempted && _hasFailed }
#else
        return false
#endif
    }

    public static var hasAttempted: Bool {
        stateQueue.sync { _hasAttempted }
    }

    // MARK: - Public – async attestation

    public static func attest(
        challengeHash: Data,
        completion: @escaping (Result<Data, AttestationError>) -> Void
    ) {
#if os(iOS)
        guard DCAppAttestService.shared.isSupported else {
            logger.info("App Attest not supported on this device — skipping")
            completion(.failure(.notSupported))
            return
        }

        DCAppAttestService.shared.generateKey { keyId, error in
            if let error {
                logger.warning("Key generation failed: \(SecurityLogger.redact(error.localizedDescription))")
                recordFailure()
                completion(.failure(.keyGenerationFailed(underlying: error)))
                return
            }
            guard let keyId else {
                recordFailure()
                completion(.failure(.keyGenerationFailed(underlying: nil)))
                return
            }

            DCAppAttestService.shared.attestKey(keyId, clientDataHash: challengeHash) { attestation, error in
                if let error {
                    logger.warning("Key attestation failed: \(SecurityLogger.redact(error.localizedDescription))")
                    recordFailure()
                    completion(.failure(.attestationFailed(underlying: error)))
                    return
                }
                guard let attestation else {
                    recordFailure()
                    completion(.failure(.attestationFailed(underlying: nil)))
                    return
                }
                // Local attestation succeeded; server must still validate before marking clean.
                logger.info("App Attest key attestation succeeded — send to server for validation")
                updateState(attempted: true, failed: false)
                completion(.success(attestation))
            }
        }
#else
        completion(.failure(.notSupported))
#endif
    }

    // MARK: - Public – async

    @available(iOS 15.0, *)
    public static func attest(challengeHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            attest(challengeHash: challengeHash) { result in
                continuation.resume(with: result)
            }
        }
    }

    // MARK: - Public – server-side outcome recording

    public static func markAttestationSucceeded() {
        updateState(attempted: true, failed: false)
        logger.info("Attestation marked as succeeded")
    }

    public static func markAttestationFailed() {
        recordFailure()
        logger.warning("Attestation marked as failed by server")
    }

    public static func reset() {
        let persist = stateQueue.sync(flags: .barrier) { () -> Bool in
            _hasAttempted = false
            _hasFailed    = false
            return _persistenceEnabled
        }
        if persist {
            persistenceQueue.async {
                AttestationStateStore.shared.clear()
            }
        }
    }

    // MARK: - Private

    private static func recordFailure() {
        updateState(attempted: true, failed: true)
    }

    /// Updates in-memory verdict state and, if `persistenceEnabled`, mirrors it to the Keychain.
    private static func updateState(attempted: Bool, failed: Bool) {
        let persist = stateQueue.sync(flags: .barrier) { () -> Bool in
            _hasAttempted = attempted
            _hasFailed    = failed
            return _persistenceEnabled
        }
        if persist {
            persistenceQueue.async {
                AttestationStateStore.shared.save(.init(hasAttempted: attempted, hasFailed: failed))
            }
        }
    }
}

// MARK: - Error

public enum AttestationError: Error {
    case notSupported
    case keyGenerationFailed(underlying: Error?)
    case attestationFailed(underlying: Error?)

    public var localizedDescription: String {
        switch self {
        case .notSupported:
            return "App Attest is not supported on this device"
        case .keyGenerationFailed(let e):
            return "Key generation failed: \(e?.localizedDescription ?? "unknown")"
        case .attestationFailed(let e):
            return "Attestation failed: \(e?.localizedDescription ?? "unknown")"
        }
    }
}
