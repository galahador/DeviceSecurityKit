//
//  FunctionAddress.swift
//  DeviceSecurityKit
//

import Foundation

/// Resolves the code address backing a Swift function value, for use with `dladdr`.
///
/// Swift function values are "thick" — a code pointer plus an optional context
/// pointer (16 bytes on 64-bit) — so `unsafeBitCast`ing one directly to
/// `UnsafeRawPointer` (8 bytes) traps with "Can't unsafeBitCast between types
/// of different sizes". The code pointer is the leading word of that
/// representation, so we read just that word out instead.
internal enum FunctionAddress {
    internal static func of<T>(_ function: T) -> UnsafeRawPointer {
        withUnsafeBytes(of: function) { raw in
            raw.load(as: UnsafeRawPointer.self)
        }
    }
}
