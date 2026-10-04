//
//  FunctionAddress.swift
//  DeviceSecurityKit
//

import Foundation

internal enum FunctionAddress {
    internal static func of<T>(_ function: T) -> UnsafeRawPointer {
        withUnsafeBytes(of: function) { raw in
            raw.load(as: UnsafeRawPointer.self)
        }
    }
}
