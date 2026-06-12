//
//  FunctionAddress.swift
//  DeviceSecurityKit
//

import Foundation

/// Resolves the code address backing a Swift function value, for use with `dladdr`.
internal enum FunctionAddress {
    internal static func of<T>(_ function: T) -> UnsafeRawPointer {
        withUnsafeBytes(of: function) { raw in
            raw.load(as: UnsafeRawPointer.self)
        }
    }
}
