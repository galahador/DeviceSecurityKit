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
    private static var _hasAttempted = false
    private static var _hasFailed    = false

    // MARK: - Public – synchronous check (reads cached state)

    public static func isAttestationFailed() -> Bool {
#if os(iOS)
        guard DCAppAttestService.shared.isSupported else { return false }
        return stateQueue.sync { _hasAttempted && _hasFailed }
#else
        return false
#endif
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
                logger.warning("Key generation failed: \(error.localizedDescription)")
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
                    logger.warning("Key attestation failed: \(error.localizedDescription)")
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
                stateQueue.sync(flags: .barrier) {
                    _hasAttempted = true
                    _hasFailed    = false
                }
                completion(.success(attestation))
            }
        }
#else
        completion(.failure(.notSupported))
#endif
    }

    // MARK: - Public – server-side outcome recording

    public static func markAttestationSucceeded() {
        stateQueue.sync(flags: .barrier) {
            _hasAttempted = true
            _hasFailed    = false
        }
        logger.info("Attestation marked as succeeded")
    }

    public static func markAttestationFailed() {
        recordFailure()
        logger.warning("Attestation marked as failed by server")
    }

    public static func reset() {
        stateQueue.sync(flags: .barrier) {
            _hasAttempted = false
            _hasFailed    = false
        }
    }

    // MARK: - Private

    private static func recordFailure() {
        stateQueue.sync(flags: .barrier) {
            _hasAttempted = true
            _hasFailed    = true
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
