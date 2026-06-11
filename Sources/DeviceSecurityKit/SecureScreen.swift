//
//  SecureScreen.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 11/06/2026.
//

#if canImport(SwiftUI)
import SwiftUI

@available(iOS 15.0, *)
public struct SecureScreenModifier<Overlay: View>: ViewModifier {
    @ObservedObject private var observable: DSKObservable
    private let overlay: Overlay

    public init(dsk: DSK = .shared, @ViewBuilder overlay: () -> Overlay) {
        self.observable = DSKObservable(dsk: dsk)
        self.overlay = overlay()
    }

    private var shouldCover: Bool {
        observable.status == .screenRecording || observable.status == .screenshotTaken
    }

    public func body(content: Content) -> some View {
        ZStack {
            content
            if shouldCover {
                overlay
            }
        }
        .animation(.easeInOut(duration: 0.2), value: shouldCover)
    }
}

@available(iOS 15.0, *)
extension View {
    public func secureScreen<Overlay: View>(
        dsk: DSK = .shared,
        @ViewBuilder overlay: @escaping () -> Overlay
    ) -> some View {
        modifier(SecureScreenModifier(dsk: dsk, overlay: overlay))
    }

    public func secureScreen(dsk: DSK = .shared) -> some View {
        secureScreen(dsk: dsk) { Color.black }
    }
}
#endif
